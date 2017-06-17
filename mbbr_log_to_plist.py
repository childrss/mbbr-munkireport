#!/usr/bin/python
"""
malwarebytes mbbr for munkireport
16May2017 childrss@gmail.com
"""
import re
import os
import plistlib
import subprocess
from datetime import datetime, timedelta


testing = 0

logfile_location="/usr/local/bin/mbbr-logs/"
#plistfileName="/usr/local/munki/preflight.d/cache/malwarebytes.plist"

last_run_time = 0
signature_version_set = 0
last_known_clean_date_set = 0
last_known_clean_date = datetime(1984,1,24,3,0,0)
last_threat_removal_attempt_date_set = 0
last_threat_removal_attempt_date = datetime(1984,1,24,3,0,0)
last_threat_removal_complete_date_set = 0
last_threat_removal_complete_date = datetime(1984,1,24,3,0,0)

eicar_count = 0
adware_count = 0
pup_count = 0
trojan_count = 0
malware_count = 0
is_files_in_quarantine = 0


# an array of dictionariess
# {'infection_detection_date': '', 'infection_name': '', 'infection_location': ''}
infections = []

# we need to figure out the mbbr machineID so we can open the log file 
proc = subprocess.Popen("/usr/local/bin/mbbr register", shell=True, stdout=subprocess.PIPE)
(out, err) = proc.communicate()
#print "program output:", out
machineIDsearch = re.search( r'Machine ID:\s*(.*)', out)
machineID = machineIDsearch.group(1)

proc = subprocess.Popen("/usr/local/bin/mbbr version", shell=True, stdout=subprocess.PIPE)
(out, err) = proc.communicate()
versionsearch = re.search( r'Program ver:\s*(.*)', out)
version = versionsearch.group(1)

proc = subprocess.Popen("/usr/local/bin/mbbr quarantine -list", shell=True, stdout=subprocess.PIPE)
(out, err) = proc.communicate()
quarantine_search = re.search( r'.*no files in quarantine.*', out)
if quarantine_search:
    is_files_in_quarantine = 0
else:
    is_files_in_quarantine = 1



if testing:
   logfile = logfile_location + "sample_mbbr_log.txt"
else:
   logfile = logfile_location + machineID + "log.txt"
print logfile

line_number = 1;
with open(logfile, 'r') as f:
    for line in reversed(list(f.readlines())):
        if line in ['\n', '\r\n']:
            pass
        else:
            try:
                line_datetime_object = datetime.strptime(line[0:19], '%Y-%m-%d %H:%M:%S')
                if not last_run_time: 
                    #pass
                    last_run_datetime_object = line_datetime_object
                    last_run_time = last_run_datetime_object.strftime('%d, %b %Y %H:%M:%S')

                if not signature_version_set:  # we only want the first reverse-match, and don't want it overriden
                   signature_version_search = re.match(r'.*signatures version (.*) \((.*)\)', line)
                   if signature_version_search:
                       signature_version = signature_version_search.group(1)
                       signature_version_date = datetime.strptime(signature_version_search.group(2), '%Y-%m-%d')
                       signature_version_set = 1
           
                if not last_threat_removal_attempt_date_set:  # we only want the first reverse-match, and don't want it overriden
                    last_threat_removal_attempt_search = re.match(r'.*: Removing detected threat.*', line)
                    if last_threat_removal_attempt_search:
                        last_threat_removal_attempt_date = line_datetime_object
                        last_threat_removal_attempt_date_set = 1
           
                if not last_threat_removal_complete_date_set:  # we only want the first reverse-match, and don't want it overriden
                    last_threat_removal_complete_search = re.match(r'.*: Threat removal complet.*', line)
                    if last_threat_removal_complete_search:
                        last_threat_removal_complete_date = line_datetime_object
                        last_threat_removal_complete_date_set = 1
           
                eicar_av_test_search = re.match(r'.*(EICAR-AV-Test.*) : (.*)', line)
                if eicar_av_test_search:
                    infections.append({'infection_detection_date': line_datetime_object, 'infection_name': eicar_av_test_search.group(1), 'infection_location': eicar_av_test_search.group(2)})
                    eicar_count += 1
            
                adware_search = re.match(r'.*(Adware.*) : (.*)', line)
                if adware_search:
                    infections.append({'infection_detection_date': line_datetime_object, 'infection_name': adware_search.group(1), 'infection_location': adware_search.group(2)})
                    adware_count += 1
            
                pup_search = re.match(r'.*(PUP.*) : (.*)', line)
                if pup_search:
                    infections.append({'infection_detection_date': line_datetime_object, 'infection_name': pup_search.group(1), 'infection_location': pup_search.group(2)})
                    pup_count += 1
            
                trojan_search = re.match(r'.*(Trojan.*) : (.*)', line)
                if trojan_search:
                    infections.append({'infection_detection_date': line_datetime_object, 'infection_name': trojan_search.group(1), 'infection_location': trojan_search.group(2)})
                    trojan_count += 1
            
                osx_search = re.match(r'.*(OSX.*) : (.*)', line)
                if osx_search:
                    infections.append({'infection_detection_date': line_datetime_object, 'infection_name': osx_search.group(1), 'infection_location': osx_search.group(2)})
                    malware_count += 1
                
                if not last_known_clean_date_set:  
                    clean_search = re.match(r'.*did not find any threats.*', line)
                    if clean_search:
                       last_known_clean_date = line_datetime_object
                       last_known_clean_date_set = 1

            except:
                print line_number, "unreadable log line : ", line  
                pass
        line_number += 1

    if testing:
        print "TESTING"
        print "mbbr_last_run_time = ", last_run_time
        print "mbbr_signature_version = ", signature_version
        print "mbbr_program_version = ", version
        print "mbbr_signature_version_date = " , signature_version_date.strftime('%d, %b %Y %H:%M:%S')
        print "mbbr_eicar_count = ",  eicar_count
        print "mbbr_adware_count = ",  adware_count
        print "mbbr_pup_count = ",  pup_count
        print "mbbr_trojan_count = ",  trojan_count
        print "mbbr_malware_count = ",  malware_count
        print "mbbr_last_known_clean_date = ",  last_known_clean_date.strftime('%d, %b %Y %H:%M:%S')
        print "mbbr_last_threat_removal_attempt_date = ",  last_threat_removal_attempt_date.strftime('%d, %b %Y %H:%M:%S')
        print "mbbr_last_threat_removal_complete_date = ",  last_threat_removal_complete_date.strftime('%d, %b %Y %H:%M:%S')
        print "mbbr_is_files_in_quarantine = ", is_files_in_quarantine
    
    pl = dict(
         mbbr_last_run_time = last_run_datetime_object,
         mbbr_signature_version = signature_version,
         mbbr_program_version = version,
         mbbr_signature_version_date =  signature_version_date,
         mbbr_eicar_count =  eicar_count,
         mbbr_adware_count =  adware_count,
         mbbr_pup_count =  pup_count,
         mbbr_trojan_count =  trojan_count,
         mbbr_malware_count =  malware_count,
         mbbr_last_known_clean_date =  last_known_clean_date,
         mbbr_last_threat_removal_attempt_date =  last_threat_removal_attempt_date,
         mbbr_last_threat_removal_complete_date =  last_threat_removal_complete_date,
         mbbr_is_files_in_quarantine = is_files_in_quarantine,
         mbbr_infections = infections
         )

# Create cache dir if it does not exist
cachedir = '%s/cache' % os.path.dirname(os.path.realpath(__file__))
if not os.path.exists(cachedir):
    os.makedirs(cachedir)

# Write mbbr report to cache
    output_plist = os.path.join(cachedir, 'malwarebytes.plist')
    plistlib.writePlist(pl, output_plist)