#!/usr/bin/env python3
import argparse

import logging
import re
import requests
import sys
import time
import traceback

from defang import refang
import pymisp
# from pymisp import MISPEvent, MISPObject
from pprint import pprint
from urllib.parse import urlparse


class misp_custom:

    def __init__(self, misp_url, misp_key, misp_ssl):
        try:
            self.misp = pymisp.PyMISP(misp_url, misp_key, misp_ssl, 'json')
        except Exception as err:
            sys.exit('Batch Job Terminated: MISP connection error - \n'+repr(err))
        self.misp_logger = logging.getLogger('mispattruploader')

    def submit_to_misp(self, misp, misp_event, misp_objects):
        '''
        Submit a list of MISP objects to a MISP event
        :misp: PyMISP API object for interfacing with MISP
        :misp_event: MISPEvent object
        :misp_objects: List of MISPObject objects. Must be a list
        '''
        # go through round one and only add MISP objects
        a = []
        for misp_object in misp_objects:
            self.misp_logger.debug(misp_object)
            if len(misp_object.attributes) > 0:
                if misp_object.name == 'network-connection':
                    template_id = 'af16764b-f8e5-4603-9de1-de34d272f80b'
                else:
                    template_id = misp.get_object_template_id(
                        misp_object.template_uuid)
                _a = misp.add_object(misp_event.id, template_id, misp_object)
                self.misp_logger.debug(_a)
                a.append(_a)
        # go through round two and add all the object references for each object
        b = []
        for misp_object in misp_objects:
            for reference in misp_object.ObjectReference:
                _b = misp.add_object_reference(reference)
                b.append(_b)
        return a, b

    def check_object_length(self, misp_objects):
        for misp_object in misp_objects:
            self.misp_logger.info(misp_object.name)
            self.misp_logger.info(dir(misp_object))
            if len(misp_object.attributes) == 0:
                self.misp_logger.error('failure to put in correct tags')
                return False
        return True

    def get_comm_and_tags(self, strInput):
        comment = None
        str_comment = ""
        tags = ["tlp:green"]
        tag_type = None
        for line in strInput.splitlines():

            if ("comment:" in line.lower()):
                vals = line.split(":", 1)
                comment = vals[1:]
            elif ("tag:" in line.lower()):
                vals = line.split(":", 1)
                value = vals[1].strip().lower()
                if "tlp" in value:
                    tags.remove("tlp:green")
                    vals_str = "tlp:"
                    vals_split = vals[1].split(":")
                    vals_str += vals_split[1]
                    tags.append(vals_str)
            elif ("type:" in line.lower()):
                vals = line.split(":", 1)
                value = vals[1].strip().lower()
                if value == "phish":
                    tag_type = value
                elif value == "malware":
                    tag_type = value
                elif value == "bec/scam":
                    tag_type = value
                elif value == "dump":
                    tag_type = value
                elif (value == "apt") or (value == "APT"):
                    tag_type = value
        if tag_type:
            self.misp_logger.info('Setting tag to ir8: %s' % tag_type)
            tag = "ir8:" + tag_type
            tags.append(tag)
        else:
            tags = None
        if comment != None:
            for c in comment:
                str_comment += c
        else:
            str_comment = comment
        return str_comment, tags

    def misp_send(self, strMISPEventID, strInput, strInfo, strUsername):
        # Establish communication with MISP.

        # The main processing block.
        try:
            objects = []
            # Get comments and tags from string input.
            str_comment, tags = self.get_comm_and_tags(strInput)
            if tags == None:
                self.misp_logger.info(
                    'Irate not in Tags: %s equals None' % tags)
                response = None
                return response
            # Setup misp objects.
            mispobj_email = pymisp.MISPObject(name="email")
            mispobj_file = pymisp.MISPObject(name="file")
            mispobj_files = {}
            mispobj_domainip = pymisp.MISPObject(name="domain-ip")
            url_no = 0
            file_no = 0
            mispobj_urls = {}

            for line in strInput.splitlines():
				# Catch domain and add to domain/IP object.
                if ("domain:" in line.lower()):
                    mispobj_domainip = pymisp.MISPObject(name="domain-ip")
                    vals = line.split(":", 1)
                    mispobj_domainip.add_attribute(
                        "domain", value=vals[1].strip(), comment=str_comment)
                    objects.append(mispobj_domainip)
                # Catch IP and add to domain/IP object.
                elif ("ip:" in line.lower()) or ("ip-dst:" in line.lower()) or ("ip-src:" in line.lower()):
                    if "domain:" in strInput.splitlines():
                        mispobj_domainip = pymisp.MISPObject(name="domain-ip")
                        vals = line.split(":", 1)
                        mispobj_domainip.add_attribute(
                            "ip", value=vals[1].strip(), comment=str_comment)
                        objects.append(mispobj_domainip)
                    else:
                        mispobj_network_connection = pymisp.MISPObject(
                            name="network-connection")
                        vals = line.split(":", 1)
                        if ("ip:" in line.lower()) or ("ip-dst:" in line.lower()):
                            mispobj_network_connection.add_attribute(
                                "ip-dst", type="ip-dst", value=vals[1].strip(), comment=str_comment)
                        else:
                            mispobj_network_connection.add_attribute(
                                "ip-src", type="ip-src", value=vals[1].strip(), comment=str_comment)
                        objects.append(mispobj_network_connection)

                # Catch email and add to email object.
                elif ("source-email:" in line.lower()) or ("email-source" in line.lower()) or ("from:" in line.lower()):
                    vals = line.split(":", 1)
                    mispobj_email.add_attribute(
                        "from", value=vals[1].strip(), comment=str_comment)
                # Catch URL and add to URL object.
                elif ("url:" in line.lower()) or (('kit:' in line.lower() or ('creds:' in line.lower())) and (('hxxp' in line.lower()) or ('http' in line.lower()))):
                    vals = line.split(":", 1)
                    url = vals[1].strip()
                    url = refang(url)
                    parsed = urlparse(url)
                    mispobj_url = pymisp.MISPObject(name="url")
                    mispobj_url.add_attribute("url", value=parsed.geturl(
                    ), category="Payload delivery", comment=str_comment)
                    if parsed.hostname:
                        mispobj_url.add_attribute(
                            "host", value=parsed.hostname, comment=str_comment)
                    if parsed.scheme:
                        mispobj_url.add_attribute(
                            "scheme", value=parsed.scheme, comment=str_comment)
                    if parsed.port:
                        mispobj_url.add_attribute(
                            "port", value=parsed.port, comment=str_comment)
                    mispobj_urls[url_no] = mispobj_url
                    url_no += 1

                # Catch different hash types, and add to file object.
                elif ("sha1:" in line.lower()) or ("SHA1:" in line):
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute(
                        "sha1", value=vals[1].strip(), comment=str_comment)
                elif ("sha256:" in line.lower()) or ("SHA256:" in line):
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute(
                        "sha256", value=vals[1].strip(), comment=str_comment)
                elif ("md5:" in line.lower()) or ("MD5:" in line):
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute(
                        "md5", value=vals[1].strip(), comment=str_comment)
                # Catch subject and add to email object.
                elif ("subject:" in line.lower()):
                    self.misp_logger.info('adding subject')
                    vals = line.split(":", 1)
                    mispobj_email.add_attribute(
                        "subject", value=vals[1].strip(), comment=str_comment)
                # catch hash|filename pair and add to file object.
                elif ("hash|filename:" in line.lower()):
                    vals = line.split(":", 1)
                    val = vals[1].split("|")
                    l_hash = val[0]
                    l_filename = val[1]
                    l_mispobj_file = pymisp.MISPObject(name="file")
                    if len(re.findall(r"\b[a-fA-F\d]{32}\b", l_hash)) > 0:
                        l_mispobj_file.add_attribute(
                            "md5", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute(
                            "filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    elif len(re.findall(r'\b[0-9a-f]{40}\b', l_hash)) > 0:
                        l_mispobj_file.add_attribute(
                            "sha1", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute(
                            "filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    elif len(re.findall(r'\b[A-Fa-f0-9]{64}\b', l_hash)) > 0:
                        l_mispobj_file.add_attribute(
                            "sha256", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute(
                            "filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    file_no += 1

            # Add all misp objects to List to be processed and submitted to MISP server as one.
            if len(mispobj_file.attributes) > 0:
                objects.append(mispobj_file)
            if len(mispobj_email.attributes) > 0:
                objects.append(mispobj_email)

            for _, u_value in mispobj_urls.items():
                if len(u_value.attributes) > 0:
                    objects.append(u_value)
            for _, f_value in mispobj_files.items():
                if len(f_value.attributes) > 0:
                    objects.append(f_value)
            # Update timestamp and event.

        except Exception:
            error = traceback.format_exc()
            response = "Error occured when converting string to misp objects:\n %s" % error
            self.misp_logger.error(response)
            return response

        if self.check_object_length(objects) != True:
            self.misp_logger.error(
                'Input from %s did not contain accepted tags.\n Input: \n%s' % (strUsername, strInput))
            return "Error in the tags you entered. Please see the guide for accepted tags."

        try:
            event = self.misp.new_event(
                info=strInfo, distribution='0', analysis='2', threat_level_id='3', published=True)
            misp_event = pymisp.MISPEvent()
            misp_event.load(event)
            self.submit_to_misp(self.misp, misp_event, objects)
            for tag in tags:
                self.misp.tag(misp_event.uuid, tag)
            self.misp.add_internal_comment(
                misp_event.id, reference="Author: " + strUsername, comment=str_comment)
            self.misp.fast_publish(misp_event.id, alert=False)
            misp_event = self.misp.get_event(misp_event.id)
            response = misp_event
            # for response in misp_event:
            if ('errors' in response and response['errors'] != None):
                return ("Submission error: "+repr(response['errors']))
            else:
                if response['Event']['RelatedEvent']:
                    e_related = ""
                    for each in response['Event']['RelatedEvent']:
                        e_related = e_related + each['Event']['id'] + ", "
                    return "Created ID: " + str(response['Event']['id']) + "\nRelated Events: " + ''.join(e_related)
                else:
                    return "Created ID: " + str(response['Event']['id'])

        except Exception:
            error = traceback.format_exc()
            response = "Error occured when submitting to misp:\n %s" % error
            self.misp_logger.error(response)
            return response
