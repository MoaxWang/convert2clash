# convert2clash

#### Analyze ss/ssr/v2ray/clashR/clash and convert it to clash config.yaml
#### Settings in convert2clash.py:
     1. sub_url = 'ubscription address' # use ';' to separate multiple addresses
     2. config_path = './template.yaml' # path to local configuration file
     3. output_path = './config.yaml' # Output path

#### Pre-requirements:
~~~
pip install -r requirements.txt
~~~
#### Solution for SSL conncection issue:
add the following into line 121
~~~
verify=False
~~~
