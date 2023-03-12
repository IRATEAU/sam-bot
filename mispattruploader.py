#!/usr/bin/env python3

""" MISP custom connector and general handler """

import sys
import traceback
import logging
import re
from urllib.parse import urlparse

from pymisp import MISPEvent, PyMISP, MISPObject
from defang import refang

class MispCustomConnector:
    """ custom MISP connector """
    def __init__(self, misp_url:str, misp_key: str, misp_ssl: bool):
        try:
            # https://pymisp.readthedocs.io/en/latest/modules.html#pymisp
            self.misp = PyMISP(misp_url, misp_key, misp_ssl)
        except Exception as err:
            sys.exit('Batch Job Terminated: MISP connection error - \n'+repr(err))
        self.misp_logger = logging.getLogger('mispattruploader')

    def submit_to_misp(self, misp: PyMISP, misp_event: MISPEvent, misp_objects: list):
        '''
        Submit a list of MISP objects to a MISP event
        :misp: PyMISP API object for interfacing with MISP
        :misp_event: MISPEvent object
        :misp_objects: List of MISPObject objects. Must be a list
        '''
        # go through round one and only add MISP objects
        misp_objects = []
        for misp_object in misp_objects:
            self.misp_logger.debug(misp_object)
            if len(misp_object.attributes) > 0:
                if misp_object.name == 'network-connection':
                    template_id = 'af16764b-f8e5-4603-9de1-de34d272f80b'
                else:
                    # self.misp_logger.debug(dir(pymisp.api))
                    # self.misp_logger.debug(dir(self.misp))
                    # exit()
                    self.misp_logger.debug(misp_object.template_uuid)
                    object_template = self.misp.get_object_template(misp_object.template_uuid)
                    template_id = object_template['ObjectTemplate']['id']
                    self.misp_logger.debug(template_id)
                self.misp_logger.debug(dir(misp_event))
                self.misp_logger.debug(misp_event)

                # add the object and get the result
                result = misp.add_object(event=misp_event, misp_object=misp_object)
                self.misp_logger.debug(result)
                misp_objects.append(result)
        # go through round two and add all the object references for each object
        misp_object_references = []
        for misp_object in misp_objects:
            for reference in misp_object.ObjectReference:

                # add the reference and get the result
                result = misp.add_object_reference(reference)
                misp_object_references.append(result)
        return misp_objects, misp_object_references

    def check_object_length(self, misp_objects: list):
        """ check object has some attributes """
        self.misp_logger.info("check_object_length called")
        for misp_object in misp_objects:
            self.misp_logger.info("got object: %s", misp_object.name)
            #self.misp_logger.info(dir(misp_object))
            if len(misp_object.attributes) == 0:
                self.misp_logger.error('failed to put in correct tags')
                return False
        return True

    def get_comm_and_tags(self, strInput: str):
        """ pull comments and tags from input """
        comment = None
        str_comment = ""
        tags = ["tlp:green"]
        tag_type = None
        for line in strInput.splitlines():

            if "comment:" in line.lower():
                vals = line.split(":", 1)
                comment = vals[1:]
            elif "tag:" in line.lower():
                vals = line.split(":", 1)
                value = vals[1].strip().lower()
                if "tlp" in value:
                    tags.remove("tlp:green")
                    vals_str = "tlp:"
                    vals_split = vals[1].split(":")
                    vals_str += vals_split[1]
                    tags.append(vals_str)
            elif "type:" in line.lower():
                vals = line.split(":", 1)
                value = vals[1].strip().lower()
                if value in ('phish', 'malware', 'bec/spam', 'dump', 'apt', 'APT'):
                    tag_type = value.lower()
                # if value == "phish":
                #     tag_type = value
                # elif value == "malware":
                #     tag_type = value
                # elif value == "bec/spam":
                #     tag_type = value
                # elif value == "dump":
                #     tag_type = value
                # elif (value == "apt") or (value == "APT"):
                #     tag_type = value
        if tag_type:
            self.misp_logger.info('Setting tag to ir8: %s', tag_type)
            tag = "ir8:" + tag_type
            tags.append(tag)
        else:
            tags = None
        if comment is not None:
            for c in comment:
                str_comment += c
        else:
            str_comment = comment
        return str_comment, tags

        ####### SLACK ENTRY POINT! ######
    def misp_send(self, strMISPEventID, strInput, strInfo, strUsername):
        """ send an event to MISP """
        try:
            objects=[]
            #get comments and tags from string input
            str_comment, tags = self.get_comm_and_tags(strInput)
            print(tags)
            if tags is None:
                self.misp_logger.info('Irate not in Tags: %s equals None', tags)
                response = None
                return response
            #setup misp objects
            mispobj_email = MISPObject(name="email")
            mispobj_file = MISPObject(name="file")
            mispobj_files = {}
            mispobj_domainip = MISPObject(name="domain-ip")
            url_no = 0
            file_no = 0
            mispobj_urls = {}

            #process input
            for line in strInput.splitlines():
                if "domain:" in line.lower(): #Catch domain and add to domain/IP object
                    mispobj_domainip = MISPObject(name="domain-ip")
                    vals = line.split(":", 1)
                    mispobj_domainip.add_attribute("domain", value=vals[1].strip(), comment=str_comment)
                    objects.append(mispobj_domainip)
                elif "ip:" in line.lower() or "ip-dst:" in line.lower() or "ip-src:" in line.lower(): #Catch IP and add to domain/IP object
                    if "domain:" in strInput.splitlines():
                        mispobj_domainip = MISPObject(name="domain-ip")
                        vals = line.split(":", 1)
                        mispobj_domainip.add_attribute("ip", value=vals[1].strip(), comment=str_comment)
                        objects.append(mispobj_domainip)
                    else:
                        mispobj_network_connection = MISPObject(name="network-connection")
                        vals = line.split(":", 1)
                        if ("ip:" in line.lower()) or ("ip-dst:" in line.lower()):
                            mispobj_network_connection.add_attribute("ip-dst", type="ip-dst", value=vals[1].strip(), comment=str_comment)
                        else:
                            mispobj_network_connection.add_attribute("ip-src", type="ip-src", value=vals[1].strip(), comment=str_comment)
                        objects.append(mispobj_network_connection)

                elif "source-email:" in line.lower() or "email-source" in line.lower() or "from:" in line.lower(): #Catch email and add to email object
                    vals = line.split(":", 1)
                    mispobj_email.add_attribute("from", value = vals[1].strip(), comment=str_comment)
                elif "url:" in line.lower() or (('kit:' in line.lower() or ('creds:' in line.lower())) and (('hxxp' in line.lower()) or ('http' in line.lower()))): #Catch URL and add to URL object
                    vals = line.split(":", 1)
                    url = vals[1].strip()
                    url = refang(url)
                    parsed = urlparse(url)
                    mispobj_url = MISPObject(name="url")
                    mispobj_url.add_attribute("url", value=parsed.geturl(), category="Payload delivery", comment=str_comment)
                    if parsed.hostname:
                        mispobj_url.add_attribute("host", value=parsed.hostname, comment=str_comment)
                    if parsed.scheme:
                        mispobj_url.add_attribute("scheme", value=parsed.scheme, comment=str_comment)
                    if parsed.port:
                        mispobj_url.add_attribute("port", value=parsed.port, comment=str_comment)
                    mispobj_urls[url_no] = mispobj_url
                    url_no += 1

                #Catch different hashes and add to file object
                elif "sha1:" in line.lower():
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute("sha1", value=vals[1].strip(),comment=str_comment)
                elif "sha256:" in line.lower():
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute("sha256", value=vals[1].strip(), comment=str_comment)
                elif "md5:" in line.lower():
                    vals = line.split(":", 1)
                    mispobj_file.add_attribute("md5", value=vals[1].strip(), comment=str_comment)
                elif "subject:" in line.lower(): #or ("subject:" in line): #Catch subject and add to email object
                    vals = line.split(":", 1)
                    self.misp_logger.info(f"adding subject: {vals[1].strip()}")
                    mispobj_email.add_attribute("subject", value = vals[1].strip(), comment=str_comment)
                elif "hash|filename:" in line.lower(): #catch hash|filename pair and add to file object
                    vals = line.split(":", 1)
                    val = vals[1].split("|")
                    l_hash = val[0]
                    l_filename = val[1]
                    l_mispobj_file = MISPObject(name="file")
                    if len(re.findall(r"\b[a-fA-F\d]{32}\b", l_hash)) > 0:
                        l_mispobj_file.add_attribute("md5", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute("filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    elif len(re.findall(r'\b[0-9a-f]{40}\b', l_hash)) > 0:
                        l_mispobj_file.add_attribute("sha1", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute("filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    elif len(re.findall(r'\b[A-Fa-f0-9]{64}\b', l_hash)) > 0:
                        l_mispobj_file.add_attribute("sha256", value=l_hash.strip(), comment=str_comment)
                        l_mispobj_file.add_attribute("filename", value=l_filename.strip(), comment=str_comment)
                        mispobj_files[file_no] = l_mispobj_file
                    file_no +=1


            #add all misp objects to List to be processed and submitted to MISP server as one.
            if len(mispobj_file.attributes) > 0:
                objects.append(mispobj_file)
            if len(mispobj_email.attributes) > 0:
                objects.append(mispobj_email)

            for u_key, u_value in mispobj_urls.items():
                if len(u_value.attributes) > 0:
                    objects.append(u_value)
            for f_key, f_value in mispobj_files.items():
                if len(f_value.attributes) > 0:
                    objects.append(f_value)
            # Update timestamp and event

        except Exception:
            error = traceback.format_exc()
            response = f"Error occured when converting string to misp objects:\n{error}"
            self.misp_logger.error(response)
            return response

        if not self.check_object_length(objects):
            self.misp_logger.error('Input from %s did not contain accepted tags.\n Input: \n%s', (strUsername, strInput))
            return "Error in the tags you entered. Please see the guide for accepted tags: (https://github.com/IRATEAU/sam-bot/blob/master/README.md)"

        try:
            # self.misp_logger.error(dir(self.misp))
            misp_event = MISPEvent()
            misp_event.info = strInfo
            misp_event.distribution = 0
            misp_event.analysis = 2
            misp_event.threat_level_id = 3
            # event.add_attribute('md5', '678ff97bf16d8e1c95679c4681834c41')
            #event = self.misp.new_event(info=strInfo, distribution='0', analysis='2', threat_level_id='3', published=False)
            #misp_event = MISPEvent()
            #misp_event.load(event)
            add = self.misp.add_event(misp_event)
            self.misp_logger.info("Added event %s", add)

            if objects:
                self.misp_logger.info("Adding objects to event...")
                objects, references = self.submit_to_misp(self.misp, misp_event, objects)
                self.misp_logger.info("References: %s", references)

            for tag in tags:
                self.misp_logger.info("Adding tag %s", tag)
                self.misp.tag(misp_event.uuid, tag)

            #self.misp.add_internal_comment(misp_event.id, reference="Author: " + strUsername, comment=str_comment)
            self.misp_logger.info("Publishing event...")
            publish_result = self.misp.publish(misp_event, alert=False)
            self.misp_logger.info("Publish result: %s", publish_result)

            if 'errors' in publish_result and publish_result.get('errors'):
                return_value = ("Submission error: "+repr(publish_result.get('errors')))
            else:
                if misp_event.get('Event',{}).get('RelatedEvent'):
                    e_related = ""
                    for each in misp_event['Event']['RelatedEvent']:
                        e_related = e_related + each['Event']['id'] + ", "
                    return_value = "Created ID: " + str(misp_event['Event']['id']) + "\nRelated Events: " + ''.join(e_related)
                else:
                    return_value = "Created ID: " + str(misp_event['Event']['id'])
            return return_value

        except Exception: #pylint: disable=broad-except
            error = traceback.format_exc()
            response = f"Error occured when submitting to MISP:\n {error}"
            self.misp_logger.error(response)
            return response
