import requests
import yaml
import base64
import json
import datetime
import sys
import urllib.parse
import re

def log(msg):
    time = datetime.datetime.now()
    print('[' + time.strftime('%Y.%m.%d-%H:%M:%S') + ']:' + msg)

# Save to files
def save_to_file(file_name, content):
    with open(file_name, 'wb') as f:
        f.write(content)

# base64 decode for URL
def safe_decode(s):
    num = len(s) % 4
    if num:
        s += '=' * (4 - num)
    return base64.urlsafe_b64decode(s)

# Decode for vmess
def decode_v2ray_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[8:]
        decode_proxy = f"{decode_proxy}{'='*(3-len(decode_proxy)%3)}"
        proxy_str = base64.b64decode(decode_proxy).decode('utf-8')
        proxy_dict = json.loads(proxy_str)
        proxy_list.append(proxy_dict)
    return proxy_list

# Decode for SS
def decode_ss_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[5:]
        if not decode_proxy or decode_proxy.isspace():
            log('[Warning] Empty Node, Ignore')
            continue
        info = dict()
        param = decode_proxy
        if param.find('#') > -1:
            remark = urllib.parse.unquote(param[param.find('#')+1:])
            info['name'] = remark
            param = param[:param.find('#')]
        if param.find('/?') > -1:
            plugin = urllib.parse.unquote(param[param.find('/?') + 2:])
            param = param[:param.find('/?')]
            for p in plugin.split(';'):
                key_value = p.split('=')
                info[key_value[0]] = key_value[1]
        if param.find('@') > -1:
            matcher = re.match(r'(.*?)@(.*):(.*)', param)
            if matcher:
                param = matcher.group(1)
                info['server'] = matcher.group(2)
                info['port'] = matcher.group(3)
            else:
                continue
            matcher = re.match(r'(.*?):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
            else:
                continue
        else:
            matcher = re.match(r'(.*?):(.*)@(.*):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
                info['server'] = matcher.group(3)
                info['port'] = matcher.group(4)
            else:
                continue
        proxy_list.append(info)
    return proxy_list

# Decode for SSR
def decode_ssr_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[6:]
        proxy_str = safe_decode(decode_proxy).decode('utf-8')
        parts = proxy_str.split(':')
        if len(parts) != 6:
            print('Fail to analyse the SSR node, link:{}'.format(node))
            continue
        info = {
            'server': parts[0],
            'port': parts[1],
            'protocol': parts[2],
            'method': parts[3],
            'obfs': parts[4]
        }
        password_params = parts[5].split('/?')
        info['password'] = safe_decode(password_params[0]).decode('utf-8')
        params = password_params[1].split('&')
        for p in params:
            key_value = p.split('=')
            info[key_value[0]] = safe_decode(key_value[1]).decode('utf-8')
        proxy_list.append(info)
    return proxy_list

# Obtain the information in subscription link
def get_proxies(urls):
    url_list = urls.split(';')
    headers = {
        'User-Agent': 'Rule2Clash'
    }
    proxy_list = {
        'proxy_list': [],
        'proxy_names': []
    }
    # Access to the subscription link
    for url in url_list:
        response = requests.get(url, headers=headers,timeout=5000).text
        try:
            raw = base64.b64decode(response)
        except Exception as r:
            log('[Warning] base64 decode failed {}'.format(r))
            log('[Info] Get Clash Node Information')
            yml = yaml.load(response, Loader=yaml.FullLoader)
            nodes_list = []
            for node in yml.get('proxies'):
                node['name'] = node['name'].strip() if node.get('name') else None
                if node.get('protocolparam'):
                    node['protocol-param'] = node['protocolparam']
                    del node['protocolparam']
                if node.get('obfsparam'):
                    node['obfs-param'] = node['obfsparam']
                    del node['obfsparam']
                node['udp'] = True
                nodes_list.append(node)
            node_names = [node.get('name') for node in nodes_list]
            log('[Info] Clash Node Num: {}'.format(len(node_names)))
            proxy_list['proxy_list'].extend(nodes_list)
            proxy_list['proxy_names'].extend(node_names)
            continue
        nodes_list = raw.splitlines()
        clash_node = []
        if nodes_list[0].startswith(b'vmess://'):
            decode_proxy = decode_v2ray_node(nodes_list)
            clash_node = v2ray_to_clash(decode_proxy)
        elif nodes_list[0].startswith(b'ss://'):
            decode_proxy = decode_ss_node(nodes_list)
            clash_node = ss_to_clash(decode_proxy)
        elif nodes_list[0].startswith(b'ssr://'):
            decode_proxy = decode_ssr_node(nodes_list)
            clash_node = ssr_to_clash(decode_proxy)
        else:
            pass
        proxy_list['proxy_list'].extend(clash_node['proxy_list'])
        proxy_list['proxy_names'].extend(clash_node['proxy_names'])
    log('[Info] Total Nodes Number: {}'.format(len(proxy_list['proxy_names'])))
    return proxy_list

# Convert v2ray to clash
def v2ray_to_clash(arr):
    log('[Info] Converting v2ray to clash')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        if item.get('ps') is None and item.get('add') is None and item.get('port') is None \
                and item.get('id') is None and item.get('aid') is None:
            continue
        obj = {
            'name': item.get('ps').strip() if item.get('ps') else None,
            'type': 'vmess',
            'server': item.get('add'),
            'port': int(item.get('port')),
            'uuid': item.get('id'),
            'alterId': item.get('aid'),
            'cipher': 'auto',
            'udp': True,
            # 'network': item['net'] if item['net'] and item['net'] != 'tcp' else None,
            'network': item.get('net'),
            'tls': True if item.get('tls') == 'tls' else None,
            'skip-cert-verify': True if item.get('tls') == 'tls' else None,
            'servername': item.get('sni') if item.get('tls') == 'tls' else None,
            'ws-path': item.get('path'),
            'ws-headers': {'Host': item.get('host')} if item.get('host') else None
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('alterId') is not None:
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('[Info] Total number of available v2ray nodes: {}'.format(len(proxies['proxy_names'])))
    return proxies

# Convert ss to clash
def ss_to_clash(arr):
    log('[Info] Converting ss to clash')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('name').strip() if item.get('name') else None,
            'type': 'ss',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'plugin': 'obfs' if item.get('plugin') and item.get('plugin').startswith('obfs') else None,
            'plugin-opts': {} if item.get('plugin') else None
        }
        if item.get('obfs'):
            obj['plugin-opts']['mode'] = item.get('obfs')
        if item.get('obfs-host'):
            obj['plugin-opts']['host'] = item.get('obfs-host')
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        proxies['proxy_list'].append(obj)
        proxies['proxy_names'].append(obj['name'])
    log('[Info] Total number of available ss nodes: {}'.format(len(proxies['proxy_names'])))
    return proxies

# Convert ssr to clash
def ssr_to_clash(arr):
    log('[Info] Converting ssr to clash')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('remarks').strip() if item.get('remarks') else None,
            'type': 'ssr',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'obfs': item.get('obfs'),
            'protocol': item.get('protocol'),
            'obfs-param': item.get('obfsparam'),
            'protocol-param': item.get('protoparam'),
            'udp': True
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('[Info] Total number of available ssr nodes: {}'.format(len(proxies['proxy_names'])))
    return proxies

# Save all servers with same mark
def unique_name(data):
    name = data.get('proxy_list')
    names = data.get('proxy_names')
    n = 0
    for i in name:
        i['name'] = names[n]= f"{i['name']}_{n}"
        n += 1
    data['proxy_list'] = name
    data['proxy_names'] = names
    return data

# Loading local configuration file
def load_local_config(path):
    try:
        f = open(path, 'r', encoding="utf-8")
        local_config = yaml.load(f.read(), Loader=yaml.FullLoader)
        f.close()
        return local_config
    except FileNotFoundError:
        log('[Warning] Fail to loading configuration')
        sys.exit()

# Add proxy into configuration
def add_proxies_to_model(data, model):
    model['proxies'] = data.get('proxy_list')
    for group in model.get('proxy-groups'):
        if group.get('proxies') is None:
            group['proxies'] = data.get('proxy_names')
        else:
            group['proxies'].extend(data.get('proxy_names'))
    return model

# Save updated configuration file
def save_config(path, data):
    config = yaml.dump(data, sort_keys=False, default_flow_style=False, encoding='utf-8', allow_unicode=True)
    save_to_file(path, config)
    log('[Info] Number of Nodes Updated: {}'.format(len(data['proxies'])))

if __name__ == '__main__':
    # use ';' to separate multiple addresses
    sub_url = 'http://sub_links_1;http://sub_links_2'
    # path to local configuration file
    config_path = './template.yaml'
    # output path
    output_path = './config.yaml'
    
    node_list = get_proxies(sub_url)
    node_list = unique_name(node_list) # Save all servers with the same mark
    default_config = load_local_config(config_path)
    final_config = add_proxies_to_model(node_list, default_config)
    save_config(output_path, final_config)
