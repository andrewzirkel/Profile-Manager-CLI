#!/usr/bin/python


import os
import sys
import optparse
import json
import csv
import codecs
import cStringIO
import getpass
from Foundation import CFPreferencesCopyAppValue
from pprint import pprint

import profilemanager


BUNDLE_ID = "se.gu.it.pmcli"


# Classes to deal with the csv module's inability to deal with Unicode, from
# http://docs.python.org/library/csv.html#examples

class UTF8Recoder:
    """
    Iterator that reads an encoded stream and reencodes the input to UTF-8
    """
    def __init__(self, f, encoding):
        self.reader = codecs.getreader(encoding)(f)
    
    def __iter__(self):
        return self
    
    def next(self):
        return self.reader.next().encode("utf-8")

class UnicodeCSVReader:
    """
    A CSV reader which will iterate over lines in the CSV file "f",
    which is encoded in the given encoding.
    """
    
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        f = UTF8Recoder(f, encoding)
        self.reader = csv.reader(f, dialect=dialect, **kwds)
    
    def next(self):
        row = self.reader.next()
        return [unicode(s, "utf-8") for s in row]
    
    def __iter__(self):
        return self

class UnicodeCSVWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.
    """
    
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()
    
    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") for s in row])
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        data = self.encoder.encode(data)
        self.stream.write(data)
        self.queue.truncate(0)
    
    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def do_test(pm, args):
    device_id = pm.add_placeholder_device("pmcli_test", serial="C080dea31")
    pm.add_device_to_group("slask", device_id)


def do_add_placeholder(pm, args):
    usage = "Usage: add_placeholder name (serial|imei|meid|udid)=value [group]"
    if len(args) not in (2, 3):
        sys.exit(usage)
    name = args[0]
    id_type, equal, ident = args[1].partition("=")
    if equal != "=":
        sys.exit(usage)
    if id_type not in ("serial", "imei", "meid", "udid"):
        sys.exit(usage)
    try:
        group = args[2]
    except IndexError:
        group = None
    device_id = pm.add_placeholder_device(name, **{id_type: ident})
    if group:
        pm.add_device_to_group(group, device_id)
    
def do_delete_device_by_identifier(pm, args):
    if len(args) != 1:
        sys.exit("Usage: delete_device_by_identifier device_identifier")
    device_identifier = args[0]
    try:
        pm.delete_device_by_identifier(device_identifier)
    except profilemanager.PMError as e:
        print e

def do_import_placeholders(pm, args):
    if len(args) != 1:
        sys.exit("Usage: import_placeholders input.csv")
    rows = list(UnicodeCSVReader(open(args[0])))
    if len(rows) < 2:
        sys.exit("Bad csv file")
    headers = rows[0]
    if headers != [u"name", u"ids", u"groups"]:
        sys.exit("Missing required column headers")
    for row in rows[1:]:
        # Empty names are displayed as "New Device" in PM.
        name = row[0] or None
        ids = dict()
        for t, _, i in [x.partition("=") for x in row[1].split("+")]:
            ids[t] = i
        device_id = pm.add_placeholder_device(name, **ids)
        if row[2]:
            for group in row[2].split("+"):
                pm.add_device_to_group(group, device_id)
    

def do_dump_devices(pm, args):
    if len(args) != 1:
        sys.exit("Usage: dump_devices output.json")
    output_fname = args[0]
    device_ids = pm.get_device_ids()
    devices = pm.get_device_details(device_ids)
    with open(output_fname, "w") as f:
        json.dump({"Devices": devices}, f, indent=4)
    

def do_dump_device_groups(pm, args):
    if len(args) != 1:
        sys.exit("Usage: dump_device_groups output.json")
    output_fname = args[0]
    group_ids = pm.get_device_group_ids()
    groups = pm.get_device_group_details(group_ids)
    with open(output_fname, "w") as f:
        json.dump({"Groups": groups}, f, indent=4)
    

def do_dump_device_group_settings(pm, args):
    if len(args) != 2:
        sys.exit("Usage: dump_device_group_settings group_name output.json")
    group_name = args[0]
    output_fname = args[1]
    knob_sets = pm.get_profile_knob_sets(group_name)
    with open(output_fname, "w") as f:
        json.dump(knob_sets, f, indent=4)
    
def do_import_device_group_settings(pm, args):
    if len(args) != 2:
        sys.exit("Usage: import_device_group_settings group_name input.json")
    dest=args[0]
    json_data=open(args[1])
    data=json.load(json_data)
    for knob_set in data:
        if knob_set == "GeneralKnobSet":
            continue
        for knob in data[knob_set]['retrieved']:
            print "Copying key " + knob_set
            pm.update_knob_sets(dest, knob_set, knob)

def do_copy_device_group_settings(pm, args):
    if (len(args) < 2) or (len(args) > 3):
        sys.exit("Usage: copy_settings source dest [payload]")
    src_group = args[0]
    dest = args[1]
    if len(args) == 3:
        payload = args[2]
    else:
        payload = None
    source_knob_sets = pm.get_profile_knob_sets(src_group)
    
    if payload:
        try:
            for knob in source_knob_sets[payload]["retrieved"]:
                #print "Copying key " + knob
                pm.update_knob_sets(dest, payload, knob)
        except KeyError:
            print("Payload for '%s' not found" % payload)
    else:
        for knob_set in source_knob_sets:
            if knob_set == "GeneralKnobSet":
                continue
            for knob in source_knob_sets[knob_set]["retrieved"]:
                print "Copying key " + knob_set
                pm.update_knob_sets(dest, knob_set, knob)
    

def do_export_placeholders(pm, args):
    if len(args) != 1:
        sys.exit("Usage: export_placeholders output.csv")
    output_fname = args[0]
    with open(output_fname, "w") as f:
        writer = UnicodeCSVWriter(f)
        writer.writerow(["name", "ids", "groups"])
        device_ids = pm.get_device_ids()
        for device in pm.get_device_details(device_ids):
            # Handle devices with empty names.
            name = device["DeviceName"] or ""
            ids = list()
            for k, v in (("SerialNumber", "serial"),
                         ("IMEI", "imei"),
                         ("MEID", "meid"),
                         ("udid", "udid"),
                        ):
                if device[k]:
                    ids.append("%s=%s" % (v, device[k]))
            idstr = "+".join(ids)
            groups = list()
            if device["device_groups"]:
                for group in pm.get_device_group_details(device["device_groups"]):
                    if group:
                        groups.append(group["name"])
            groupstr = "+".join(groups)
            writer.writerow([name, idstr, groupstr])
    

def main(argv):
    p = optparse.OptionParser()
    p.set_usage("""Usage: %prog [options] verb""")
    p.add_option("-s", "--server")
    p.add_option("-u", "--username")
    p.add_option("-p", "--password")
    p.add_option("-P", "--prompt-password", action="store_true")
    options, argv = p.parse_args(argv)
    if len(argv) < 2:
        print >>sys.stderr, p.get_usage()
        return 1
    
    verbs = dict()
    for name, func in globals().items():
        if name.startswith("do_"):
            verbs[name[3:]] = func
    
    action = argv[1]
    if action not in verbs:
        sys.exit("Unknown verb %s" % action)
    
    server = options.server or CFPreferencesCopyAppValue("server", BUNDLE_ID)
    if not server:
        sys.exit("No server specified")
    username = options.username or CFPreferencesCopyAppValue("username", BUNDLE_ID)
    if not username:
        sys.exit("No username specified")
    password = options.password or CFPreferencesCopyAppValue("password", BUNDLE_ID)
    if options.prompt_password or not password:
        password = getpass.getpass("Password for %s@%s: " % (username, server))
    if not password:
        sys.exit("No password specified")
    
    pm = profilemanager.ProfileManager(server)
    try:
        pm.authenticate(username, password)
        verbs[action](pm, list(x.decode("utf-8") for x in argv[2:]))
    except profilemanager.PMError as e:
        sys.exit(e)
    
    return 0
    

if __name__ == '__main__':
    sys.exit(main(sys.argv))
    
