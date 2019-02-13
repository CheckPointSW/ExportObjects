from __future__ import print_function

import argparse
import csv
import getpass
import json
import os
import re
import subprocess
import sys

from cpapi import APIClient, APIClientArgs, APIClientException, APIException


def process_args_and_login(parser=None, client=None, showparameter=None, fields=None):
    # initializing command line arguments and variables to be used later
    args = args_initializer(parser=parser, param=showparameter)
    global debug
    global log_file
    if not showparameter:
        showparameter = args.showparameter[0] if args.showparameter else None
    if not fields:
        try:
            fields = {
                "whitelist": args.fields,
                "blacklist": [],
                "translate": []
            }
        except AttributeError:
            fields = {
                "whitelist": [],
                "blacklist": [],
                "translate": []
            }
    management = args.management[0] if args.management else None
    domain = args.domain[0] if args.domain else None
    debug = None
    log_file = None
    if args.debug[0] == "on":
        debug = True
    if (debug or __debug__) and args.log_file is not None:
        try:
            log_file = open(args.log_file, "wb")
        except IOError:
            debug_log("Could not open given log file for writing, sending debug information to stderr.")
    # open the output file if given one
    output_file = open(args.output[0], "wb") if args.output else None
    output_file_format = args.format[0].lower()
    user_created = (args.user_created[0].lower() == "true") if args.user_created else True

    # trying to get login credentials
    username, password, session_id = get_login_credentials(args.username[0] if args.username else None,
                                                           args.password[0] if args.password else None,
                                                           args.session_id[0] if args.session_id else None,
                                                           args.session_file[0] if args.session_file else None,
                                                           args.root[0] if args.root else None)
    debug_log(
        "Got the following login credentials:\n    Username: {0}\n    Password: {1}\n    Session ID: {2}".format(
            username, '*' * len(password) if password else None, session_id))
    if not args.root or args.root[0] == "true":
        unsafe = (args.unsafe[0] == "true")
        unsafe_auto_accept = (args.unsafe_auto_accept[0] == "true")
        if not client:
            client = APIClient(APIClientArgs(server=management))
        if unsafe or (unsafe_auto_accept and validate_fingerprint_without_prompt(client, management,
                                                                                 auto_accept=unsafe_auto_accept)) or client.check_fingerprint():
            login(client, management, domain, username, password, session_id)
        else:
            raise APIClientException(
                "The server's fingerprint is different than your local record of it. The script cannot operate in this unsecure manner (unless running with --unsafe). Exiting...")
    else:
        login(client, management, domain, session_id=session_id, username=None, password=None)
    return output_file, output_file_format, user_created, client, args


# Validate the fingerprint of the server with a local one
# If it's validated, assign the API client's fingerprint accordingly
# If not, display an error and exit.
def validate_fingerprint_without_prompt(client, server, auto_accept=False, local_fingerprint=None):
    # If given a fingerprint, save it so we don't have to give it next time
    if local_fingerprint:
        client.save_fingerprint_to_file(server, local_fingerprint)
    # If not given a fingerprint, try to read one from a file previously written
    else:
        local_fingerprint = client.read_fingerprint_from_file(server)
    # Getting the server's fingerprint
    server_fingerprint = client.get_server_fingerprint(server)
    if local_fingerprint.replace(':', '').upper() == server_fingerprint.replace(':', '').upper():
        client.fingerprint = local_fingerprint
        client.save_fingerprint_to_file(server, client.fingerprint)
        return True
    elif auto_accept:
        print(
            "Accepting the fingerprint " + server_fingerprint + ".\n Please note that this is unsafe and you may be a victim to a Man-in-the-middle attack.",
            file=sys.stderr)
        client.fingerprint = server_fingerprint
        client.save_fingerprint_to_file(server, client.fingerprint)
        return True
    else:
        print("Cannot operate on an unverified server. Please verify the server's fingerprint: '"
              + server_fingerprint + "' and add it via the 'fingerprint' option of this module.", file=sys.stderr)
        return False


def get_data(client, showparameter=None, dependency_solver_args=None):
    # getting the raw JSON data from the management server
    data = get_raw_data(param=showparameter, client=client)
    if data is None:
        print("Could not get data", file=sys.stderr)
        sys.exit(1)

    if not dependency_solver_args or "singular_type" not in dependency_solver_args:
        singular_type = showparameter[:-1]
    else:
        singular_type = dependency_solver_args["singular_type"]
    # if we were told to solve dependencies (i.e. present the group that has no other groups as children first, so we can load them in the correct order)
    if dependency_solver_args:
        if "children_keys" in dependency_solver_args and dependency_solver_args["children_keys"]:
            dependency_loader = DependencyLoader(data, singular_type, dependency_solver_args["children_keys"],
                                                 client=client)
        else:
            dependency_loader = DependencyLoader(data, singular_type, client=client)
        data, extras = dependency_loader.order_data()
    return data


def get_objects(showparameter=None, fields=None, dependency_solver_args=None):
    # TODO: investigate if necessary
    #      |
    #      V
    if fields is None:
        fields = {}
    if dependency_solver_args is None:
        dependency_solver_args = {}
    output_file, output_file_format, user_created, client, args = process_args_and_login(showparameter=showparameter,
                                                                                         fields=fields)
    data = get_data(client, showparameter=showparameter if showparameter else args.showparameter[0],
                    dependency_solver_args=dependency_solver_args)
    export_json(data, fields, output_file=output_file, output_file_format=output_file_format, user_created=user_created)
    print("Done.", file=sys.stderr)


def export_json(data, fields, output_file, output_file_format, user_created, append=False):
    # extracting from it the fields we need in the form we need
    extracted_fields = format_objects(data, fields, output_file_format, user_created=user_created)
    fields_order = get_fields_order_and_replace(extracted_fields, fields["whitelist"] if "whitelist" in fields else [],
                                                fields["translate"] if "translate" in fields else [])
    # outputting the data to the output file (if one doesn't exist, outputting to stdout) in the given format
    write_data(extracted_fields, output_file, output_file_format, fields_order=fields_order, append=append)


# getting the raw JSON data from the management server for commands such as show-...s
def get_raw_data(param, payload=None, container_keys="objects", client=None):
    if isinstance(container_keys, basestring):
        container_keys = [container_keys]
    # trying to log in to the management server
    if not payload:
        payload = {}
    # initializing the API's generator for our query.
    result_data = {}
    results = client.gen_api_query("show-" + param, payload=payload, container_keys=container_keys,
                                   details_level="full")

    # now iterating over the generator, getting new objects in each iteration
    # this loop is meant to show progress and to gather all the objects to one APIResponse object.
    for current_res in results:
        if not current_res.success:
            print("Failed to retrieve the required information.\n" + str(current_res.error_message),
                  file=sys.stderr)
            # if the API call failed because of a wrong session id, login with username and password and try again
            if current_res.error_message.startswith("Wrong session id"):
                username, password = get_username_and_password()
                client.sid = login(client, client.server, client.domain, username, password)
                results = client.gen_api_query("show-" + param, details_level="full")
                current_res = results.next()
            else:
                sys.exit(1)
        if current_res.data["total"] == 0:
            print("1 object received.", file=sys.stderr)
        else:
            print(str(current_res.data["to"]) + '/' + str(current_res.data["total"]) + " objects retrieved.",
                  file=sys.stderr)

        # if done querying the API and got all the objects, save the result:
        if "total" not in current_res.data or current_res.data["total"] == 0 or current_res.data["to"] == \
                current_res.data["total"]:
            for key in container_keys:
                result_data[key] = current_res.data[key] if key in current_res.data else {}
    lst = sum((result_data[key] for key in container_keys), [])
    return lst


# formatting the objects we got into the format we need them in
# fields_dict = {
#     "whitelist": [ ... ]
#     "blacklist": [ ... ]
#     "translate": [ ... ]
def format_objects(data, fields_dict, output_file_format, user_created=True, dummy_creator_config=None,
                   unexportable_objects=None, client=None, layer=""):
    extracted_fields = {}
    global_keys = {}
    results = []
    # A list of uid's of objects that the script processed already, to avoid duplicates
    uids = []
    type = ""
    change_whitelist = False
    for i in range(len(data)):
        if data[i]["uid"] in uids:
            # Ignore duplicate objects
            continue
        uids.append(data[i]["uid"])
        try:
            if data[i] is None or (user_created and data[i]["domain"]["name"] == "Check Point Data"):
                continue
        except KeyError:
            # because it doesn't have the field "domain", then we don't care about it
            pass
        # flatten the json of each object that is shown
        # debug_log("pre-flattening JSON data of object #" + str(i) + ":\n" + json.dumps(data[i]))
        flat = flatten_json(data[i])
        type = flat["type"]
        # debug_log("flattened JSON data of object #" + str(i) + ":\n" + json.dumps(flat))
        res = {}

        # this loop removes unnecessary dicts and lists and adds the good values to extracted_fields
        for key in flat.keys():
            try:
                if isinstance(flat[key], (list, dict)):
                    del flat[key]
                    continue
                # in the end of most if not all keys there is going to be a '.' at the end of the key.
                # this removes that dot
                if key[-1] == '.':
                    flat[key[:-1]] = flat[key]
                    del flat[key]
                    continue
            # if the key does not exist for a certain object, it doesn't matter, therefore: pass.
            except KeyError:
                pass
        # if certain fields were requested, insert them into res for further processing.
        # if not, just copy the whole dict for the next step
        if "whitelist" in fields_dict:
            if len(fields_dict["whitelist"]) > 0:
                for pattern in fields_dict["whitelist"]:
                    for key in flat.keys():
                        # match keys with the given patterns
                        if key_matches(key, pattern):
                            res[key] = flat[key]
                            # we don't need to check if something that is already approved matches another field in the whitelist
                            del flat[key]
            else:
                res = flat
        else:
            res = flat
            change_whitelist = True
        if "blacklist" in fields_dict:
            for pattern in fields_dict["blacklist"]:
                for key in res.keys():
                    if key_matches(key, pattern):
                        del res[key]
        if "replace-data" in fields_dict:
            for pattern in fields_dict["replace-data"]:
                for key in res.keys():
                    if key_matches(key, pattern[0]):
                        for tup in pattern[1]:
                            match_object = key_matches(res[key], tup[0])
                            if match_object:
                                res[key] = tup[1](match_object.group(1))
        # keeping count of all of the keys we are going to show.
        # using a dict for O(1) avg search instead of O(n) with a list of keys
        for key in res.keys():
            zfilled_key = zfill_key(key)
            if key != zfilled_key:
                res[zfilled_key] = res[key]
                del res[key]
                key = zfilled_key
            if key not in global_keys:
                global_keys[key] = True
            # also, checking for objects we can't export and replacing them as specified in dummy_creator_config
            if unexportable_objects:
                if res[key] in unexportable_objects:
                    field = "__default"
                    for k in dummy_creator_config.keys():
                        if key_matches(key, k):
                            field = k
                            break
                    # checking if I already created that object
                    if "__created" not in unexportable_objects[res[key]]:
                        unexportable_objects[res[key]]["__instances"] = []
                        unexportable_objects[res[key]]["__created"] = False

                        self_comments = dummy_creator_config[field][2].format(unexportable_objects[res[key]]["type"],
                                                                              unexportable_objects[res[key]]["name"])
                        if "comments" in res:
                            res["comments"] += ("\n" if res["comments"] else "") + self_comments
                        try:
                            unexportable_objects[res[key]]["comments"] += ("\n" if unexportable_objects[res[key]][
                                "comments"] else "") + self_comments
                        except (TypeError, KeyError):
                            # if it doesn't have a comments field, we don't really care.
                            pass

                    instance = {
                        "layer": res["layer"] if "layer" in res else layer,
                        "type": type,
                        "field": key,
                        "original-object-type": unexportable_objects[res[key]]["type"],
                        "exported-object-type": dummy_creator_config[field][0].format(
                            unexportable_objects[res[key]]["type"], unexportable_objects[res[key]]["name"]),
                        "original-object-name": unexportable_objects[res[key]]["name"],
                        "exported-object-name": dummy_creator_config[field][1].format(
                            unexportable_objects[res[key]]["type"], unexportable_objects[res[key]]["name"]),
                    }
                    if instance["type"] == "access-rule":
                        instance["position"] = res["position"]
                    unexportable_objects[res[key]]["__instances"].append(instance)
                    unexportable_objects[res[key]]["__original_name"] = unexportable_objects[res[key]]["name"]
                    unexportable_objects[res[key]]["__original_type"] = unexportable_objects[res[key]]["name"]
                    unexportable_objects[res[key]]["name"] = dummy_creator_config[field][1].format(
                        unexportable_objects[res[key]]["type"], unexportable_objects[res[key]]["name"])
                    res[key] = unexportable_objects[res[key]]["name"]
        results.append(res)

    # this loop is meant to add spaces where there is no data for a certain key
    for key in global_keys:
        for res in results:
            if key not in res:
                res[key] = None
            if key in extracted_fields:
                extracted_fields[key].append("" if res[key] is None and output_file_format == "csv" else res[key])
            else:
                extracted_fields[key] = [res[key]]
    if change_whitelist is True:
        fields_dict["whitelist"] = extracted_fields.keys()

    return extracted_fields


# searches for values that are matched with keys that match the regex
def search_dict(dictionary, regex):
    result = []
    if isinstance(regex, basestring):
        regex = re.compile(regex)
    for key in dictionary:
        if key_matches(key, regex):
            result.append((key, dictionary[key]))
    return result


'''
# function that returns whether a key matches a certain pattern:
# patterns are as presented in these examples:
# [key]              [pattern]   [V/X]
# name               name          V
# name               nam           X
# groups             groups        V
# groups.1.members   groups        V
# groups.1.members   groups.*      V
# groups.1.members.1 *.*.*.*       V
# groups.1.name      *.*.*.*       X
def key_matches(key, pattern):
    # pattern is empty string (meaningless)
    if not pattern:
        return False
    # we have processed the key until this index
    current_key_index = 0
    # for counting the level (number of dots in the key)
    key_dots = 0
    # we have processed the pattern until this index
    current_pattern_index = 0
    # for counting the level (number of dots in the pattern)
    pattern_dots = 0
    # while until we're done processing the pattern
    while current_pattern_index < len(pattern):
        try:
            key_dot_index = key.index('.', current_key_index)
            key_dots += 1
        except ValueError:
            key_dot_index = len(key)
        try:
            pattern_dot_index = pattern.index('.', current_pattern_index)
            pattern_dots += 1
        except ValueError:
            pattern_dot_index = len(pattern)
        if key_dots < pattern_dots:
            return False
        if pattern[current_pattern_index:pattern_dot_index] != '*' and key[current_key_index:key_dot_index] != pattern[current_pattern_index:pattern_dot_index]:
            return False
        current_key_index = key_dot_index + 1
        current_pattern_index = pattern_dot_index + 1
    if key[current_key_index:len(pattern[current_pattern_index:])] == pattern[current_pattern_index:]:
        return True
    return False
'''


def key_matches(key, pattern):
    if pattern:
        if isinstance(pattern, basestring):
            return re.search(re.escape(pattern) if isinstance(pattern, unicode) else pattern, key)
        else:
            return pattern.search(key)
    return False


# outputting the data to the output file (if one doesn't exist, outputting to stdout) in the given format
def write_data(jsondata, output_file, file_format, fields_order=None, append=False, close_file=True):
    if output_file is None:
        output_file = sys.stdout
    if "json" in file_format:
        json.dump(jsondata, output_file, indent=4)
    else:
        res = flat_json_to_csv(jsondata, fields_order)
        writer = csv.writer(output_file)
        writer.writerows(res)
    if close_file and (output_file is not None and output_file is not sys.stdout):
        output_file.close()


# merges the source dict into the dest dict, with each key in dest starting with prepend, resulting in a flat dict
def merge_flat_dicts(dest, source, prepend):
    if source is None:
        return
    elif not isinstance(source, dict):
        dest[prepend] = source
        return
    for key in source.keys():
        dest[prepend + key] = source[key]


# merging 2 dicts (shallow-copy) without duplicates
def merge_dicts_without_duplicates(x, y, dont_include_keys=None):
    if y is None or not isinstance(y, dict) or len(y.keys()) == 0 or x == y:
        return x
    if not x:
        x = y
        return x
    if isinstance(y[y.keys()[0]], list):
        # all of the fields have the same length (and are filled with `None`s if irrelevant/undefined/unknown)
        len_items_in_y = get_dict_len(y)
        len_items_in_x = get_dict_len(x)
        for key in y.keys():
            if key not in x:
                x[key] = [None] * len_items_in_x
        for i in range(len_items_in_y):
            for j in range(len_items_in_x):
                found_duplicate = True
                # if this i-th element in y is equal in every key to the j-th element in x
                for key in y.keys():
                    # this equal sign comparison works because these dicts are flat at this level
                    if len(x[key]) <= j or x[key][j] != y[key][i]:
                        found_duplicate = False
                        break  # it's different in some way! we break out and try the next object in x to see if maybe it matches our object in y.
                if found_duplicate:  # it's a new element
                    break
            if not found_duplicate:
                for key in x.keys():
                    if key in y and len(y[key]) > i:
                        x[key].append(y[key][i])
                    else:
                        x[key].append(None)
    else:
        for key in y.keys():
            if dont_include_keys is None or key not in dont_include_keys:
                x[key] = merge_dicts_without_duplicates(x[key] if key in x else {}, y[key])
    return x


# merging two lists without duplicates
def merge_fields_order(order1, order2):
    res = order1
    for field in order2:
        if field not in order1:
            res.append(field)
    return res


# gets the amount of items in a dict in the form of data_dict
def get_dict_len(d):
    maxlen = 0
    for key in d.keys():
        if len(d[key]) > maxlen:
            maxlen = len(d[key])
    return maxlen


# unravels a json tree into a dict with all the key-value pairs on the first level, with keys written as follows: 'k1.k2.7.k3' (7 for signifying the 8th element in the list k2)
def flatten_json(jsondata):
    if isinstance(jsondata, dict):
        jdkeys = jsondata.keys()
        for key in jdkeys:
            merge_flat_dicts(jsondata, flatten_json(jsondata[key]), key + '.')
        return jsondata
    # converts the list into a dict like this: { '1': value-1, '2': value-2, ... }
    if isinstance(jsondata, list):
        length = len(jsondata)
        res = {}
        for i in range(length):
            merge_flat_dicts(res, flatten_json(jsondata[i]), str(i) + '.')
        return res
    return jsondata


# returns a list which contains the items that are different between one list and another
# note: not commutative (diff(a, b) != diff(b, a)).
def diff(first, second):
    second = set(second)
    return [item for item in first if item not in second]


# converts flat json from flatten_json() to a csv string to be written to a file
def flat_json_to_csv(jsondata, fields_order, print_column_names=True):
    res = []
    ordered_keys = order_fields(jsondata.keys(), fields_order) if fields_order is not None else sorted(jsondata.keys())
    res.append(ordered_keys)
    # find max length to go through in lists:
    maxlen = 0
    for key in ordered_keys:
        if len(jsondata[key]) > maxlen:
            maxlen = len(jsondata[key])
    for i in range(maxlen):
        lst = []
        for key in ordered_keys:
            lst.append(str(jsondata[key][i]) if (len(jsondata[key]) > i and jsondata[key][i] is not None) else "")
        res.append(lst)
    return res


def compile_regexes(fields):
    if "whitelist" in fields:
        for i in range(len(fields["whitelist"])):
            fields["whitelist"][i] = re.compile(fields["whitelist"][i])
    if "blacklist" in fields:
        for i in range(len(fields["blacklist"])):
            fields["blacklist"][i] = re.compile(fields["blacklist"][i])
    if "translate" in fields:
        for item in fields["translate"]:
            item = (re.compile(item[0], re.IGNORECASE),
                    [(re.compile(replacewithitem[0], re.IGNORECASE), re.compile(replacewithitem[1], re.IGNORECASE)) for
                     replacewithitem in item[1]])
    if "replace-data" in fields:
        for item in fields["replace-data"]:
            item = (re.compile(item[0], re.IGNORECASE),
                    [(re.compile(replacewithitem[0], re.IGNORECASE), replacewithitem[1]) for replacewithitem in
                     item[1]])
    return fields


# generates a list of the ordered fields as they should be
def get_fields_order_and_replace(fields, whitelist, translate):
    indexer = {}
    fields_order = []
    for i in range(len(translate)):
        indexer[translate[i][0]] = i

    # replace items in the field names
    for i in range(len(whitelist)):
        temp_keys = []
        if whitelist[i] in indexer.keys():
            for key in fields.keys():
                if key_matches(key, translate[indexer[whitelist[i]]][0]):
                    final_key = key
                    for sub_pair in translate[indexer[whitelist[i]]][1]:
                        final_key = re.sub(sub_pair[0], sub_pair[1], final_key)
                        fields[final_key] = fields[key]
                        del fields[key]
                    split_final_key = final_key.split('.')
                    for j in range(len(split_final_key)):
                        if is_int(split_final_key[j]):
                            split_final_key[j] = split_final_key[j].zfill(4)
                    temp_keys.append(zfill_key(final_key))
            del indexer[whitelist[i]]
        else:
            for key in fields.keys():
                if key_matches(key, whitelist[i]):
                    temp_keys.append(zfill_key(key))
        fields_order += sorted(temp_keys)
    # iterate over the list of remaining items in indexer, those that don't fit in a specific whitelisted field. general replacer
    for k, v in indexer.iteritems():
        for i in range(len(fields_order)):
            if key_matches(fields_order[i], k):
                for sub_pair in translate[v][1]:
                    fields_order[i] = re.sub(sub_pair[0], sub_pair[1], fields_order[i])
        for key in fields.keys():
            if key_matches(key, k):
                final_key = key
                for sub_pair in translate[v][1]:
                    final_key = re.sub(sub_pair[0], sub_pair[1], final_key)
                    fields[final_key] = fields[key]
                    del fields[key]
    return remove_duplicates(fields_order)


# fills a key that looks like this: groups.0.members.1
# with `z` zeroes as padding for each number.
# example result: groups.0000.members.0001
def zfill_key(key, z=4):
    split_key = key.split('.')
    for j in range(len(split_key)):
        if is_int(split_key[j]):
            split_key[j] = split_key[j].zfill(z)
    return ".".join(split_key)


def is_int(str):
    try:
        int(str)
        return True
    except ValueError:
        return False


# order list via key_matches and the whitelisted fields (named `order` here)
def order_fields(lst, order):
    indexer = {}
    lstcopy = list(lst)
    for i in range(len(lst)):
        try:
            indexer[order[i]] = i
            lstcopy.remove(order[i])
        except IndexError:
            indexer[lstcopy[0]] = i
            del lstcopy[0]
        except ValueError:
            pass
    return sorted(lst, key=lambda d: indexer[d])


# prints debugging information to a file if a debug flag was set when starting python, in the program arguments
def debug_log(string, extra_log_file=None):
    if __debug__ or debug:
        # if we have a log file set by a program argument flag
        if extra_log_file is not None:
            print(string, file=extra_log_file)
            return
        #        if log_file is not None:
        #            print(string, file=log_file)
        #            return
        print(string, file=sys.stderr)


# several methods of getting login credentials
def get_login_credentials(args_username=None, args_password=None, args_session_id=None, args_session_file=None,
                          args_root=None):
    username = args_username
    password = args_password
    session_id = args_session_id

    debug_log("Trying to get login credentials...")
    if session_id or username and password:
        return username, password, session_id

    # trying to log in via `mgmt_cli login -r true` if possible
    debug_log("Trying to login via `mgmt_cli login -r true.")
    if args_root == "true":
        try:
            mgmt_cli_path = os.path.expandvars("$CPDIR") + "/bin/mgmt_cli"
            session_id = \
            json.loads(subprocess.check_output([mgmt_cli_path, "login", "-r", "true", "-f", "json"], shell=False))[
                "sid"]
            return username, password, session_id
        except ValueError as err:
            print(err, file=sys.stderr)
        except OSError as err:
            print(err, file=sys.stderr)
        except Exception as err:
            print(err, file=sys.stderr)

    # trying to get session_id from file (if one exists)
    if args_session_file:
        debug_log("Trying to get session-id from a given session-file")
        try:
            session_file = open(args_session_file, "r")
            json_string = ""
            potential_sid = ""
            for line in session_file:
                json_string += line
                if line.split(':')[0] == "sid":
                    potential_sid = line.split('\"')[1]
            try:
                session_id = json.loads(json_string)["sid"]
            except ValueError:  # it's not a json file
                session_id = potential_sid
            return username, password, session_id
        except IOError:
            print("Could not open given session file. Trying to login with username and password.", file=sys.stderr)

    username, password = get_username_and_password(args_username, args_password)

    return username, password, session_id


# input function to get username and password interactively from stdin
def get_username_and_password(username=None, password=None):
    debug_log("Trying to get username and password.")
    # getting username and password if nothing else worked
    if username is None:
        username = raw_input("Enter username: ")
    if password is None:
        # getpass only works in a tty:
        if sys.stdin.isatty():
            password = getpass.getpass("Enter password: ")
        else:
            print("Attention! Your password will be shown on the screen!", file=sys.stderr)
            password = raw_input("Enter password: ")
    return username, password


# filling the APIClient with login credentials so it can perform actions that require authorization
def login(client, management, domain, username=None, password=None, session_id=None):
    # will use the given session-id to perform actions
    if session_id:
        client.sid = session_id
        return session_id
    # will try to login using the given username and password
    else:
        login_res = client.login(username, password, domain=domain)
        if not login_res.success:
            print("Login failed: {}".format(login_res.error_message), file=sys.stderr)
            exit(1)
    return login_res.res_obj["data"]["sid"]


# this dependency loader makes sure that if for example an object contains another object (groups for example), the child object and its child objects will be exported too, preventing an error.
class DependencyLoader(object):
    group_types = ["group", "group-with-exclusion", "service-group", "time-group"]

    def __init__(self, list, type, children_keys=None, parents_keys=None, client=None):
        self.children_keys = children_keys if children_keys else ["members"]
        self.parents_keys = parents_keys if parents_keys else ["groups"]
        # dictionary that matches uid's with DependencyTreeNodes.
        self.treenodes_map = {}
        self.type = type
        self.client = client
        self.list = [self.DependencyTreeNode(self, item, type, children_keys=children_keys, parents_keys=parents_keys,
                                             client=client) for item in list]

    def order_data(self):
        # uid list of the objects in order, so all of the "dependency" groups are showed before the "dependent" groups
        uidlist = []
        result = []
        extras = []
        for k, v in self.treenodes_map.iteritems():
            # it has no parents -> it is a root of a tree
            if not v.parents:
                uidlist += v.postorder_traverse()
        uidlist = remove_duplicates(uidlist)
        # reordering the data so we can now process it
        for uid in uidlist:
            # if its details-level is full:
            if self.is_full_details(uid):
                item = self.treenodes_map[uid].data
            else:
                item = self.get_full_details(uid)
            if item["type"] == self.type:
                result.append(item)
            else:
                extras.append(item)
        return result, extras

    def is_full_details(self, uid):
        if "type" in self.treenodes_map[uid].data:
            for key in self.children_keys + self.parents_keys:
                if key in self.treenodes_map[uid].data:
                    if isinstance(self.treenodes_map[uid].data[key], dict):
                        if "uid" not in self.treenodes_map[uid].data[key] or uid in self.treenodes_map[uid].data[
                            key] and not self.is_full_details(self.treenodes_map[uid].data[key]["uid"]):
                            return False
                    elif isinstance(self.treenodes_map[uid].data[key], list):
                        if len(self.treenodes_map[uid].data[key]) > 0 and not isinstance(
                                self.treenodes_map[uid].data[key][0], dict):
                            return False
            return True
        return False

    def get_full_details(self, uid):
        try:
            obj = self.client.api_call("show-object", {"uid": uid, "details-level": "full"}).data["object"]
        # couldn't get the object:
        except (AttributeError, APIClientException, APIException) as e:
            debug_log(str(e))
            return None
        else:
            for key in self.children_keys + self.parents_keys:
                if key in obj and len(obj[key]) > 0 and not isinstance(obj[key][0], dict):
                    for i in range(len(obj[key])):
                        obj[key][i] = self.get_full_details(obj[key][i])
            if uid in self.treenodes_map:
                self.treenodes_map[uid].data = obj
            else:
                self.DependencyTreeNode(self, obj, obj["type"], client=self.client)
            return obj

    class DependencyTreeNode(object):
        def __init__(self, dependency_loader, data, type, children_keys=None, parents_keys=None, client=None):
            self.dependency_loader = dependency_loader
            self.type = type
            if not isinstance(data, dict):
                data = {"uid": data}
            # contains a dictionary that matches a uid to the full object
            self.get_map[data["uid"]] = self
            self.data = data
            self.uid = data["uid"]
            # list of uid's
            self.children = []
            self.parents = []
            if not self.dependency_loader.is_full_details(self.uid):
                res = dependency_loader.get_full_details(self.uid)
                if res:
                    self.data = res
            temp_parents = []
            if children_keys is None:
                children_keys = ["members"]
            if parents_keys is None:
                parents_keys = ["groups"]
            for key in parents_keys:
                if self.data and key in self.data:
                    if isinstance(self.data[key], list):
                        temp_parents += self.data[key]
                    else:
                        temp_parents += [self.data[key]]
            temp_members = []
            for key in children_keys:
                if self.data and key in self.data:
                    if isinstance(self.data[key], list):
                        temp_members += self.data[key]
                    else:
                        temp_members += [self.data[key]]
            if temp_parents is not None:
                for parent in temp_parents:
                    if isinstance(parent, dict):
                        if parent["uid"] in self.get_map.keys():
                            self.parents.append(parent["uid"])
                            self.get_map[parent["uid"]].children.append(self.uid)
                        # it's a uid:
                        else:
                            self.parents.append(
                                DependencyLoader.DependencyTreeNode(self.dependency_loader, parent, type,
                                                                    children_keys=children_keys,
                                                                    parents_keys=parents_keys, client=client).uid)
            if temp_members is not None:
                for member in temp_members:
                    if isinstance(member, dict):
                        if member["uid"] in self.get_map.keys():
                            self.children.append(member["uid"])
                            self.get_map[member["uid"]].parents.append(self.uid)
                        # it's a uid:
                        else:
                            self.children.append(
                                DependencyLoader.DependencyTreeNode(self.dependency_loader, member, type,
                                                                    children_keys=children_keys,
                                                                    parents_keys=parents_keys, client=client).uid)

                    # the member is only referenced by uid
                    else:
                        if member in self.get_map.keys():
                            self.children.append(member)
                            self.get_map[member].parents.append(self.uid)
                        else:
                            self.children.append(
                                DependencyLoader.DependencyTreeNode(self.dependency_loader, member, type,
                                                                    children_keys=children_keys,
                                                                    parents_keys=parents_keys, client=client).uid)

        # returns uid's from the postorder traversal of the tree (root is self)
        def postorder_traverse(self):
            result = []
            for child in self.children:
                result += self.get_map[child].postorder_traverse()
            result.append(self.uid)
            return remove_duplicates(result)

        @property
        def get_map(self):
            return self.dependency_loader.treenodes_map


# removes duplicates from a list while preserving order
def remove_duplicates(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


# parses program arguments using argparse
def args_initializer(parser=None, param=None):
    if parser is None:
        parser = argparse.ArgumentParser(description="This script takes ")
    if param is None:
        parser.add_argument(nargs=1, dest="showparameter", default=["hosts"],
                            help="The data to show { hosts, networks, groups, ... }\nDefault: hosts")
        parser.add_argument(nargs='*', dest="fields", help="The fields to show\nDefault: show all the fields")
    parser.add_argument("-o", "--output", required=False, nargs=1, help="Name of output file.")
    parser.add_argument("-f", "--format", required=False, default=[os.getenv('MGMT_CLI_FORMAT', "csv")], nargs=1,
                        choices=["csv", "json"],
                        help="Response format.\nDefault: csv\nEnvironment variable: MGMT_CLI_FORMAT")
    parser.add_argument("-u", "--username", required=False, default=[os.getenv('MGMT_CLI_USER')], nargs=1,
                        help="Management administrator user name.\nEnvironment variable: MGMT_CLI_USER")
    parser.add_argument("-p", "--password", required=False, nargs=1,
                        help="Management administrator password.\nEnvironment variable: MGMT_CLI_PASSWORD")
    parser.add_argument("-m", "--management", required=False, default=[os.getenv('MGMT_CLI_MANAGEMENT', "127.0.0.1")],
                        nargs=1,
                        help="Management server IP address.\nDefault: 127.0.0.1\nEnvironment variable: MGMT_CLI_MANAGEMENT")
    parser.add_argument("--port", required=False, default=[os.getenv('MGMT_CLI_PORT', 443)], nargs=1,
                        help="Port of the management server\nDefault: 443\nEnvironment variable: MGMT_CLI_PORT")
    parser.add_argument("-d", "--domain", required=False, nargs=1, default=[os.getenv('MGMT_CLI_DOMAIN')],
                        help="Name, uid or IP-address of the management domain.\nEnvironment variable: MGMT_CLI_DOMAIN")
    parser.add_argument("-s", "--session-file", required=False, nargs=1, default=[os.getenv('MGMT_CLI_SESSION_FILE')],
                        help="File containing session information retrieved by login.\nEnvironment variable: MGMT_CLI_SESSION_FILE")
    parser.add_argument("--session-id", required=False, nargs=1, default=[os.getenv('MGMT_CLI_SESSION_ID')],
                        help="Established session identifier (sid) using login.\nEnvironment variable: MGMT_CLI_SESSION_ID")
    parser.add_argument("-r", "--root", required=False, nargs=1,
                        choices=["true", "false"],
                        help="When running on the management server, use this flag with value set to 'true' to login as Super User administrator.\nDefault: false")
    parser.add_argument("--user-created", required=False, dest="user_created", nargs=1, default=["true"],
                        choices=["true", "false"],
                        help="Show only user created data.\nDefault: true")
    parser.add_argument("--debug", required=False, nargs=1, default=[os.getenv('MGMT_CLI_DEBUG', 'off')],
                        choices=["on", "off"],
                        help="Whether to run the command in debug mode.\nDefault: off\nEnvironment variable: MGMT_CLI_DEBUG")
    parser.add_argument("--log-file", required=False, nargs=1,
                        default=os.getenv('MGMT_CLI_LOG_FILE', "get_objects.log"),
                        help="Path to the debugging log file\nDefault: get_objects.log\nEnvironment variable: MGMT_CLI_LOG_FILE")
    parser.add_argument("-x", "--proxy", required=False, nargs=1, default=[os.getenv('MGMT_CLI_PROXY')],
                        help="Proxy settings.    {user:password@proxy.server:port}\nEnvironment variable: MGMT_CLI_PROXY")
    parser.add_argument("--unsafe", required=False, default=["false"], choices=["true", "false"],
                        help="UNSAFE! Ignore certificate verification.    {true/false}\nDefault {false}")
    parser.add_argument("--unsafe-auto-accept", required=False, default=["false"], choices=["true", "false"],
                        help="UNSAFE! Auto accept fingerprint during certificate verification.   {true/false}\nDefault {false}")
    return parser.parse_args()


if __name__ == "__main__":
    get_objects()
