#!/usr/bin/env python3
# -*- coding=utf-8 -*-


import os, json; from typing import List, Dict

def win32metadata():
    ''' https://github.com/ynkdir/py-win32more/raw/main/json/Windows.Win32.json.xz '''





wtf = json.load( open('win32metadata\\windows.win32.json', 'r') )


def parse_argv(api: Dict):
    '''  '''
    prefix = ''
    for idx in range(len(api["Signature"]["ParameterTypes"])):
        param_type = api["Signature"]["ParameterTypes"][idx]
        if 'Type' != param_type["Kind"] or not 'PROC' in param_type['Name']:
            continue
        count = list(filter(lambda item: item['Namespace'] == param_type['Namespace'] and item['Name'] == param_type['Name'], wtf))
        if len(count) == 1 and str(count[0]['BaseType']).endswith('Delegate'):
            prefix = param_type['Name']; break

    if prefix:
        a = ['0'] * len(api["Signature"]["ParameterTypes"])
        a[idx] = f'{prefix}(code)'
        return ', '.join(a)

    raise Exception('not found')
        

for item in wtf:
    if item['Name'] != "Apis": continue
    for api in item['MethodDefinitions']:

        try:
            template = \
            "[](void* code) {" + os.linesep + \
            "    std::cout << \"" + api["Import"]["Name"] + "\";" + os.linesep + \
            "    " + api["Import"]["Name"] + "(" + parse_argv(api) + ");" + os.linesep + \
            "},"
            print(template)
        except:
            pass