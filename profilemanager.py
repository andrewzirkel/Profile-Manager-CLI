#Tested to server version 4 (OSX 10.10)

import os
import json
import urllib
import urllib2
import cookielib
import hashlib
import mimetools


class PMError(BaseException):
    pass

class ProfileManager(object):
    
    def __init__(self, server, scheme="https"):
        super(ProfileManager, self).__init__()
        self.debug=False
        self.sessionGUID=None
        self.server = server
        self.api = '/devicemanagement/webapi'
        self.scheme = scheme
        self.headers = dict()
        self.cookiejar = cookielib.CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar))
        #self.groups_by_id = None
        self.groups_by_name = None
        self.pmversion="1"
    
#    def create_request(self, path, data=None):
#        return urllib2.Request("%s://%s%s" % (self.scheme, self.server, path), data, self.headers)
    
    def create_request(self, path, data=None, type=None):
        req = urllib2.Request("%s://%s%s" % (self.scheme, self.server, path), data, self.headers)
        if data:
            if self.pmversion!=1: #10.8 doesn't need this
                req.add_header('Content-Type', 'application/json; charset=UTF-8')
            if type=="auth":
                req.get_method = lambda: 'PUT'
        return req
    
#    def open(self, path, data=None):
#        return self.opener.open(self.create_request(path, data))
    
    def open_or_die(self, path, data=None, type=None):
        if self.debug:
            print "To MDM: " + path
            print data
        r = self.opener.open(self.create_request(path, data, type))
        if r.getcode() != 200:
            raise PMError("Server error: %d" % r.getcode())
        rc = r.read()
        if self.debug and r.info().getplist():
            print "From MDM:"
            print rc
        return rc
    
    def do_auth_magic(self, magic):
        r = self.open_or_die("/collabdproxy", json.dumps(magic), "auth")
        return json.loads(r)
    
    def authenticate(self, username, password):
        try:
            self.username = username
            self.password = password
            # Load login form and get cookie.
            r = self.open_or_die("/auth")
            # Set sessionGUID from cookie - other cookie members: name, path, domain, port, value
            for cookie in self.cookiejar:
                if cookie.name == "cc.collabd_session_guid":
                    self.sessionGUID = cookie.value
            if self.sessionGUID:
                self.pmversion="2"
            if self.pmversion=="1":
            # Request CSRF token. - v2 uses a different authentication scheme
                r = self.open_or_die("/auth/csrf")
                csrf_token = r.rstrip()
                # Add token to request headers.
                self.headers["X-CSRF-Token"] = csrf_token
                # Request auth challenge.
                r = self.open_or_die("/auth/challenge_advanced", "username=%s\n" % username)
                challenge_data = r.rstrip()
                if not challenge_data.startswith("Digest "):
                    raise PMError("Unrecognized auth challenge")
            else:
                # Set sessionGUID from cookie - other cookie members: name, path, domain, port, value
                for cookie in self.cookiejar:
                    if cookie.name == "cc.collabd_session_guid":
                        self.sessionGUID = cookie.value
            
                jsondata={"type":"com.apple.BatchServiceRequest","requests":[{"type":"com.apple.ServiceRequest","arguments":[self.username,True],"sessionGUID":self.sessionGUID,"serviceName":"AuthService","methodName":"challengeForUsername:advanced:","expandReferencedObjects":False}]}
                r = self.do_auth_magic(jsondata)
                # Digest nonce="ivnOFZibtwTI5F9/qQhedEkjsBYjSKnxMnTaxrxrCMp4MmR8",realm="GU",qop="auth",algorithm=md5-sess
                challenge_data = r['responses'][0]["response"]
                if not challenge_data.startswith("Digest "):
                    raise PMError("Unrecognized auth challenge")
            
            challenge = dict()
            for item in challenge_data[7:].split(","):
                k, _, v = item.partition("=")
                if v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                challenge[k] = v
            # Authenticate with digest.
            ncvalue = "%08x" % 1
            method = "AUTHENTICATE"
            uri = "/"
            cnonce = os.urandom(8).encode("hex")
            realm = challenge["realm"]
            nonce = challenge["nonce"]
            qop = challenge["qop"]
            algorithm = challenge["algorithm"]
            if algorithm.lower() != "md5-sess":
                raise PMError("Unsupported auth algorithm %s" % repr(algorithm))
            md5 = lambda x: hashlib.md5(x).digest()
            md5_hex = lambda x: hashlib.md5(x).hexdigest()
            ha1=hashlib.new("md5")
            ha1.update(md5("%s:%s:%s" % (username, realm, password)))
            ha1.update(":")
            ha1.update(nonce)
            ha1.update(":")
            ha1.update(cnonce)
            ha1 = ha1.hexdigest()
            ha2 = md5_hex("%s:%s" % (method, uri))
            response = md5_hex(":".join((ha1, nonce, ncvalue, cnonce, qop, ha2)))
            digest_dict = {
                "username": username,
                "realm": realm,
                "nonce": nonce,
                "uri": uri,
                "qop": qop,
                "nc": ncvalue,
                "cnonce": cnonce,
                "algorithm": algorithm,
                "response": response,
            }
            data = "Digest " + ",".join('%s="%s"' % (k, v) for k, v in digest_dict.items())
            if self.pmversion=="this isn't used":
                r = self.open_or_die("/auth/digest_login", data)
                result = json.loads(r)
                # {"auth_token":"D9D47C7D-F3E3-4214-8416-9B4DBB09F530","success":true}
                if not result["success"]:
                    raise PMError("Authentication failed")
                self.auth_token = result["auth_token"]
            else:
                jsondata={"type":"com.apple.BatchServiceRequest","requests":[{"type":"com.apple.ServiceRequest","arguments":[data,True],"sessionGUID":self.sessionGUID,"serviceName":"AuthService","methodName":"validateUsernameAndPasswordDigest:remember:","expandReferencedObjects":False}]}          
                r = self.do_auth_magic(jsondata)
                if not r["responses"][0]["succeeded"]:
                    raise PMError("Authentication failed")
                #auth_token is sessionGUID for 10.9
                self.auth_token = self.sessionGUID
        except urllib2.URLError as e:
            raise PMError(e.reason)
        try:
            # Send auth_token to authentication callback.
            r = self.open_or_die("/devicemanagement/api/authentication/callback?auth_token=%s" % self.auth_token)
            self.api = '/devicemanagement/api'
        except urllib2.URLError as e:
            try:
                r = self.open_or_die("/devicemanagement/webapi/authentication/callback?auth_token=%s" % self.auth_token)
                self.api = '/devicemanagement/webapi'
            except urllib2.URLError as e:
                raise PMError(e.reason)
            
    
    def do_magic(self, magic):
        r = self.open_or_die("%s/magic/do_magic?auth_token=%s" % (self.api, self.auth_token), json.dumps(magic))
        return json.loads(r)
    
    def add_placeholder_device(self, name, serial=None, imei=None, meid=None, udid=None):
        args = dict()
        args["DeviceName"] = name
        if serial is not None:
            args["SerialNumber"] = serial
        if imei is not None:
            args["IMEI"] = imei
        if meid is not None:
            args["MEID"] = meid
        if udid is not None:
            args["udid"] = udid
        response = self.do_magic({"device":
            {"create":
                [[args]]
            }
        })
        try:
            device_id = response["result"]["device"]["created"][0]["id"]
        except:
            raise PMError("Couldn't add device")
        return device_id
    
    def delete_device(self, device_id):
        if (self.pmversion==1):
            response = self.do_magic({"device":{"destroy":[[device_id]]}})
        else:
            response = self.do_magic({"device":{"destroy":[device_id]}})
        return response
    
    def add_device_to_group(self, group_name, device_id):
        group_id = self.get_group(group_name)["id"]
        print group_id
        if (self.pmversion==1):
            response = self.do_magic({"device_group": {"add_device": [[group_id, {"id": [device_id]}]]}})
        else:
            response = self.do_magic({"device_group": {"add_device": [[group_id, {"id": device_id}]]}})

    #search for device and return array of ids
    def search_device(self,search_string):
        result = self.do_magic({"device": {"find_matching_detailed":[[{"search_string":search_string},"GIMME"]]}})
        id = result["remote"]["GIMME"][0][1:]
        return id
    
    #remove device from all device groups
    #returns None if no devices found, and result if the device is removed
    def delete_device_by_identifier(self, device_identifier):
        id = self.search_device(device_identifier)
        if len(id) == 0:
            raise PMError("No Device found with the identifier %s" % device_identifier)
        if len(id) > 1:
            raise PMError("Multiple devices found with the identifier %s" % device_identifier)
        result = self.delete_device(id)
        return result
  
    def get_device_ids(self):
        response = self.do_magic({"device": {"find_all": [["GIMME"]]}})
        return response["remote"]["GIMME"][0][1:]
    
    def get_device_details(self, device_ids):
        return self.do_magic({
            "device": {
                "get_complete_details": [[None, {"ids": device_ids}]]
            }
        })["result"]["device"]["retrieved"]
    
    def get_device_group_ids(self):
        response = self.do_magic({"device_group": {"find_all": [["GIMME"]]}})
        return response["remote"]["GIMME"][0][1:]
    
    def get_device_group_details(self, group_ids):
        return self.do_magic({
            "device_group": {
                "get_details": [[None, {"ids": group_ids}]]
            }
        })["result"]["device_group"]["retrieved"]
    
    #def get_device_group_profiles(self, name):
    #    group = self.get_group(name)
    #    return self.do_magic({"device_group": {"get_profiles": [[group["id"]]]}})
    
    def get_profile_knob_sets(self, group_name):
        group = self.get_group(group_name)
        if 'profiles' in group:
            return self.do_magic({"profile": {"get_knob_sets": [[group["profiles"]]]}})["result"]
        #Somewhere around 3.2.2 key changed to profile
        if 'profile' in group:
            return self.do_magic({"profile": {"get_knob_sets": [[group["profile"]]]}})["result"]
        raise PMError('No Profile for group.')
    
    # Update or Create one "knob" knobname with content data to dest.
    def update_knob_sets(self, group_name, knobname, data):
        try:
            ddata = self.get_profile_knob_sets(group_name)
        except:
            raise PMError("No settings configured for this group. General tab must be configured first.")
        profileid = ddata["GeneralKnobSet"]["retrieved"][0]["profile"]
        if 'retrieved' in ddata[knobname]:
            knobset = ddata[knobname]["retrieved"]
            for knob in knobset:
                # Some sets don't use PayloadDisplayName, even though it is present.
                if knobname == "CertificateKnobSet":
                    print("CertificateKnobSet not supported")
                    return
                if knobname == "AdCertKnobSet":
                    if knob["Description"] == data["Description"]:
                        knobid = knob["id"]
                        break
                    else:
                        knobid = None
                elif knobname == "InterfaceKnobSet":
                    if (knob["Interface"] == data["Interface"]) and (knob["SSID_STR"] == data["SSID_STR"]):
                        knobid = knob["id"]
                    else:
                        knobid = None
                else:
                    if 'PayloadUUID' in knob:
                        PayloadUUID = knob['PayloadUUID']
                    if knob["PayloadDisplayName"] == None:
                        knobid = knob["id"]
                        break
                    elif knob["PayloadDisplayName"] == data["PayloadDisplayName"]:
                        knobid = knob["id"]
                        break
                    else:
                        knobid = None
        else:
            knobid = None
        data["profile"] = profileid
        if knobid is not None:
            data["id"] = knobid
            if PayloadUUID:
                data['PayloadUUID'] = PayloadUUID
            response = self.do_magic({knobname: {"update": [[knobid, data]]}})
        else:
            del data["id"]
            del data['PayloadUUID']
            response = self.do_magic({knobname: {"create": [[data]]}})
    
    def load_groups(self):
        if self.groups_by_name is None:
            #self.groups_by_id = dict()
            self.groups_by_name = dict()
            for group in self.get_device_group_details(self.get_device_group_ids()):
                #self.groups_by_id[group_id] = group
                self.groups_by_name[group["name"]] = group
    
    def get_group(self, name):
        self.load_groups()
        try:
            return self.groups_by_name[name]
        except KeyError:
            raise PMError("No such group %s" % repr(name))
    

