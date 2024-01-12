import os
import secrets
import string
import subprocess
import re
import paramiko
import getpass
import time
import select

hostname_pattern = re.compile(r'^gapit.*$')

ipv4_pattern = re.compile(r'(172)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|'
                         r'[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])')
ipv4_wg_pattern = re.compile(r'(10)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}'
                             r'|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])')
ttl_ping_pattern = re.compile(r'time=\d')
api_token_pattern = re.compile(r'gapit.*admin')
api_token_final_pattern = re.compile(r'\S*')

ssh_client = paramiko.SSHClient()
pod_host = '10.20.30.40'
pod_port = 22
wg_pod_username = 'gapit'
pod_password = 'gapit1'
old_wg_ip = '10.12.14.2'
wireguard_file = '/etc/wireguard/wg0.conf'
private_key_patch = '/home/marius/.ssh/id_rsa'
known_hosts_home = '/home/marius/.ssh/known_hosts'
known_hosts_root = '/root/.ssh/known_hosts'
wireguard_host = '95.179.142.161'
#passphrase = getpass.getpass(prompt='Enter the passphrase for your private key: ')
public_key_path_1 = '/home/marius/.ssh/id_rsa.pub'
public_key_path_2 = '/root/.ssh/id_rsa.pub'
public_key_path_3 = '/home/marius/salt-deployment-without-master/salt-config/pki/ssh/salt-ssh.rsa.pub'
restart_wg = "bash -c 'sudo systemctl restart wg-quick@wg0.service'"
ssh_known_hosts = os.path.expanduser('~/.ssh/known_hosts')
gf_all_python = 'GF_all.py'
gf_all_temp = 'GF_all.py.template'
netplan_file = '/etc/netplan/00-installer-config.yaml'


def replaceCharsInTuple(tuple):
    # Clean up IP-addresses in tuple and return as string
    tupleToReturn = tuple.replace(',', '.').replace('(', '').replace(')', '').replace(' ', '').replace('\'', '')
    return ''.join(tupleToReturn)

def main():
    alphabet = string.ascii_letters + string.digits
    server_password = ''.join(secrets.choice(alphabet) for i in range(18))
    portainer_password = ''.join(secrets.choice(alphabet) for i in range(18))
    alerta_password = ''.join(secrets.choice(alphabet) for i in range(18))
    grafana_sec_password = ''.join(secrets.choice(alphabet) for i in range(18))
    grafana_postgres_password = ''.join(secrets.choice(alphabet) for i in range(18))
    influx_password = ''.join(secrets.choice(alphabet) for i in range(18))

    public_key_1 = subprocess.check_output(['cat', public_key_path_1], text=True)
    public_key_2 = subprocess.check_output(['sudo', 'cat', public_key_path_2], text=True)
    public_key_3 = subprocess.check_output(['sudo', 'cat', public_key_path_3], text=True)
    hostname_array = []
    ipv4_array = []
    ipv4_wg_array = []
    with open('Hostname-ip', 'r+') as f:
        for line in f:
            hostname_matches = re.findall(hostname_pattern, line)
            ipv4_matches = re.findall(ipv4_pattern, line)
            ipv4_wg_matches = re.findall(ipv4_wg_pattern, line)
            for i in range(len(hostname_matches)):
                hostname_array.append(hostname_matches[i])
            for i in range(len(ipv4_matches)):
                ipv4_array.append(replaceCharsInTuple(str(ipv4_matches[i])))
            for i in range(len(ipv4_wg_matches)):
                ipv4_wg_array.append(replaceCharsInTuple(str(ipv4_wg_matches[i])))

    for i in range(len(hostname_array)):
        os.system(f'ssh-keygen -f "{known_hosts_home}" -R "10.20.30.40"')
        os.system(f'sudo ssh-keygen -f "{known_hosts_root}" -R "10.20.30.40"')
        if os.path.exists(ssh_known_hosts):
            ssh_client.load_host_keys(ssh_known_hosts)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh_client.connect(pod_host, pod_port, wg_pod_username, pod_password)
            ssh_client.save_host_keys(ssh_known_hosts)
            install_key_1 = (f"echo \"{public_key_1}\" >> /home/gapit/.ssh/authorized_keys")
            install_key_2 = (f"echo \"{public_key_2}\" >> /home/gapit/.ssh/authorized_keys")
            install_key_3 = (f"echo \"{public_key_3}\" >> /home/gapit/.ssh/authorized_keys")
            stdin, stdout, stderr = ssh_client.exec_command(install_key_1)
            if stderr.read():
                print(f"Error executing command: {install_key_1}")
            stdin, stdout, stderr = ssh_client.exec_command(install_key_2)
            if stderr.read():
                print(f"Error executing command: {install_key_2}")
            stdin, stdout, stderr = ssh_client.exec_command(install_key_3)
            if stderr.read():
                print(f"Error executing command: {install_key_3}")
            stdin, stdout, stderr = ssh_client.exec_command('cat /etc/machine-id')
            machine_id = stdout.read().decode().strip()

            change_password_gapit = f"echo 'gapit:{server_password}' | sudo chpasswd"
            stdin, stdout, stderr = ssh_client.exec_command(change_password_gapit)
            output = stdout.read().decode().strip()
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"Error: {error_output}")
            else:
                print("Password for user gapit changed successfully to: " + server_password)

            change_hostname = f"sudo hostnamectl set-hostname {hostname_array[i]}"
            stdin, stdout, stderr = ssh_client.exec_command(change_hostname)

            replace_wireguardip = f"sudo sed -i 's/{old_wg_ip}/{ipv4_wg_array[i]}/g' {wireguard_file}"
            stdin, stdout, stderr = ssh_client.exec_command(replace_wireguardip)
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"Error: {error_output}")
            else:
                print(f"IP address '{old_wg_ip}' replaced with '{ipv4_wg_array[i]}' in {wireguard_file}")

            stdin, stdout, stderr = ssh_client.exec_command(restart_wg)

            stdin, stdout, stderr = ssh_client.exec_command('sudo cat /etc/wireguard/publickey')
            wg_publickey = stdout.read().decode().strip()

        finally:
            ssh_client.close()
            os.system(f'sudo rm -rf {known_hosts_root}')
            os.system(f'sudo cp {known_hosts_home} /root/.ssh/')

        try:
            #private_key = paramiko.RSAKey.from_private_key_file(private_key_patch, password=passphrase)
            ssh_client.connect(wireguard_host, pod_port, wg_pod_username)

            wg_config = f"[peer]\nPublicKey = {wg_publickey}\nAllowedIPs = {ipv4_wg_array[i]}/32\n##Name " \
                        f"= {hostname_array[i]}"

            append_lines = (
            "sudo bash -c '"
            "echo \"\" >> /etc/wireguard/wg0.conf; "
            "echo \"[peer]\" >> /etc/wireguard/wg0.conf; "
            f"echo \"PublicKey = {wg_publickey}\" >> /etc/wireguard/wg0.conf; "
            f"echo \"AllowedIPs = {ipv4_wg_array[i]}/32\" >> /etc/wireguard/wg0.conf; "
            f"echo \"##Name = {hostname_array[i]}\" >> /etc/wireguard/wg0.conf'"
            )

            stdin, stdout, stderr = ssh_client.exec_command(append_lines)
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"Error: {error_output}")
                quit()
            print(f"The following has been added to wg0.conf:\n{wg_config}")

            stdin, stdout, stderr = ssh_client.exec_command(restart_wg)
            time.sleep(20)
            ping_test = f"ping {ipv4_wg_array[i]} -c 4"
            stdin, stdout, stderr = ssh_client.exec_command(ping_test)
            ping_result = stdout.read().decode().strip()
            ping_matches = re.findall(ttl_ping_pattern, ping_result)
            if not ping_matches:
                print('Ping test failed. Wireguard connection is not up!')
                quit()
            else:
                print('Wireguard connections is up')


        finally:
            ssh_client.close()

        #with open('/home/marius/salt-deployment-without-master/run_salt_config.sh', 'w+') as f:
            #f.write(salt_script)

        target_ip="10.20.30.40"
        username="gapit"
        pubkey_path="/home/marius/.ssh/id_rsa.pub"
        customer="GM"
        customer_site="DC4"

        print('Starting salt commands...')
        # Set vault CLI grains to be able to send in passwords from command line
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.set standalone_gapitstack:vault_key cli-pillar-auth")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.get standalone_gapitstack:vault_key")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.set gapit:customer \"{customer}\"")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.set gapit:customer_site \"{customer_site}\"")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Alerta
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_alerta")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Grafana
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_grafana")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # InfluxDB 2
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_influxdb2")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Node-red
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_node-red")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Ginspector
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_ginspector")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Gapit modbus
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" grains.append gapit:stack standalone_gapitmodbus")
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" --sudo "
                  f"\"{target_ip}\" saltutil.sync_grains")
        # Grafana plugins
        os.system(f"sudo salt-ssh --user \"{username}\" --sudo \"{target_ip}\" cmd.run 'mkdir -p "
                  f"/var/lib/gapit/grafanaplugins'")
        os.system(f"sudo salt-ssh --user \"{username}\" --sudo \"{target_ip}\" cmd.run 'wget -P /tmp "
                  f"https://github.com/gapitio/gapit-htmlgraphics-panel/releases/download/v2.1.1/gapit-htmlgraphics-"
                  f"panel-2.1.1.zip && unzip /tmp/gapit-htmlgraphics-panel-2.1.1.zip -d /var/lib/gapit/grafanaplugins'")
        os.system(f"sudo salt-ssh --user \"{username}\" --sudo \"{target_ip}\" cmd.run 'wget -P /tmp "
                  f"https://github.com/grafana/grafana-json-datasource/releases/download/v1.3.6/marcusolsson-"
                  f"json-datasource-1.3.6.zip && unzip /tmp/marcusolsson-json-datasource-1.3.6.zip -d "
                  f"/var/lib/gapit/grafanaplugins'")
        # State apply
        os.system(f"sudo salt-ssh --config-dir salt-config --log-file salt-log/ssh  --user \"{username}\" "
                  f"--sudo \"{target_ip}\" state.apply  pillar='{{\"cli-pillar-auth\": {{\"data\": "
                  f"{{\"portainer_admin_username\": \"admin\", \"portainer_admin_password\": "
                  f"\"\'$PORTAINER_ADMIN_PASSWORD\'\", \"alerta_postgres_superuser\": \"postgres\", "
                  f"\"alerta_postgres_superuser_password\": \"\'$ALERTA_POSTGRES_SUPERUSER_PASSWORD\'\", "
                  f"\"grafana_security_admin_password\": \"\'$GRAFANA_SECURITY_ADMIN_PASSWORD\'\", "
                  f"\"grafana_postgres_superuser\": \"grafana\", \"grafana_postgres_superuser_password\": "
                  f"\"\'$GRAFANA_POSTGRES_SUPERUSER_PASSWORD\'\",\"influxdb2_admin_user\": \"admin\","
                  f"\"influxdb2_admin_password\": \"\'$INFLUXDB2_ADMIN_PASSWORD\'\"}}}}}}'")

        try:
            ssh_client.connect(pod_host, pod_port, wg_pod_username, pod_password)

            api_generate = 'sudo docker exec influx2 influx auth create --org gapit --all-access -d gapit'
            stdin, stdout, stderr = ssh_client.exec_command(api_generate)
            api_output = stdout.read().decode().strip()
            error_code = stderr.read().decode().strip()
            api_token_match = re.findall(api_token_pattern, api_output)
            api_token = str(api_token_match[0])
            api_token = api_token.replace('gapit', '').replace('admin', '').replace(' ', '')
            api_token_final_match = re.findall(api_token_final_pattern, api_token)
            api_token_final_match = [value for value in api_token_final_match if value != '']
            api_token_final = str(api_token_final_match[0])

            os.chdir(f'{gf_location}')
            os.system(f'cp {gf_all_temp} {gf_all_python}')
            os.system(f"sed -i 's/dummy-password-value/{grafana_sec_password}/g' {gf_all_python}")
            os.system(f"sed -i 's/dummy-token-value/{api_token_final}/g' {gf_all_python}")
            os.system(f'python3 {gf_all_python}')
            os.system(f'rm -rf {gf_all_python}')

            change_subnet = f"sed -i 's/\/24/\/22/g' {netplan_file}"
            change_ip = f"sed -i 's/10.20.30.40/{ipv4_array[i]}"

        finally:
            ssh_client.close()

        with open(hostname_array[i] + '.txt', 'w+') as f:
            f.write(f'Hostname: {hostname_array[i]}\n')
            f.write(f'Machine-id: {machine_id}\n')
            f.write(f'Gapit server password: {server_password}\n')
            f.write(f'Portainer password: {portainer_password}\n')
            f.write(f'Alerta password: {alerta_password}\n')
            f.write(f'Grafana security password: {grafana_sec_password}\n')
            f.write(f'Grafana postgres password: {grafana_postgres_password}\n')
            f.write(f'Influx password: {influx_password}\n')
            f.write(f'Wireguard IP: {ipv4_wg_array[i]}\n')
            f.write(f'LAN IP: {ipv4_array[i]}\n')
            f.write(f'Api token: {api_token_final}\n')


if __name__ == '__main__':
    main()
