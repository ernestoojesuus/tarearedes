import os
import re
import csv
import sys
import logging
import controlPrograma as con

MAX_COUNT = 300000000000000
#Directory where the parsed information is going to get written
OUTPUT_FP = os.path.join(os.getcwd(),"output")

class ProgramArgs:

    def __init__(self,argv):
        self.args = argv[1:]

        self.csv_log_fp = None
        self.web_log_fp = None
        self.rsvp_fp = None
        self.access_fp = None

    def check_args(self):

        n = len(self.args)
        i = 0
        while i < n:
            arg = self.args[i] 

            if arg in ('-w','--web'):
                if not self.web_log_fp:
                    if i + 1== n:
                        logging.error("Error: Argument '{}': No value provided.".format(arg))
                        exit(1)

                    file_path = self.args[i + 1]
                    if not os.path.exists(file_path):
                        logging.error("Error: Argument '{}': File path '{}'' doesn't exist.".format(arg,file_path))
                        exit(1)

                    self.web_log_fp = file_path

            elif arg in ('-r','--rsvp'):
                if not self.rsvp_fp:
                    if i + 1== n:
                        logging.error("Error: Argument '{}': No value provided.".format(arg))
                        exit(1)

                    file_path = self.args[i + 1]
                    if not os.path.exists(file_path):
                        logging.error("Error: Argument '{}': File path '{}'' doesn't exist.".format(arg,file_path))
                        exit(1)

                    self.rsvp_fp = file_path

            elif arg in ('-a','--access'):
                if not self.access_fp:
                    if i + 1== n:
                        logging.error("Error: Argument '{}': No value provided.".format(arg))
                        exit(1)

                    file_path = self.args[i + 1]
                    if not os.path.exists(file_path):
                        logging.error("Error: Argument '{}': File path '{}'' doesn't exist.".format(arg,file_path))
                        exit(1)

                    self.access_fp = file_path

                else:
                    logging.error("Error: Argument '{}' duplicated.".format(arg))
                    exit(1)
            elif arg in ('-c','--csv'):
                if not self.csv_log_fp:
                    if i + 1== n:
                        logging.error("Error: Argument '{}': No value provided.".format(arg))
                        exit(1)

                    file_path = self.args[i + 1]
                    if not os.path.exists(file_path):
                        logging.error("Error: Argument '{}': File path '{}'' doesn't exist.".format(arg,file_path))
                        exit(1)

                    self.csv_log_fp = file_path

                else:
                    logging.error("Error: Argument '{}' duplicated.".format(arg))
                    exit(1)

            else:
                if not self.web_log_fp:
                    file_path = arg
                    if not os.path.exists(file_path):
                        logging.error("Error: Argument '{}': File path '{}'' doesn't exist.".format(arg,file_path))
                        exit(1)

                    self.web_log_fp = file_path

            i += 1


def print_how_to_use():
    print("error: use parser_logs <-a|-r|-w|-c> <file path>")
    print("-a|-access : says the file path is for an access log")
    print("-r|-rsvp : says the file path is for a rsvp log")
    print("-w|-web : says the file path is for a web log")
    print("-c|-csv : says the file path is for a csv file with hosts")
    print("example 1:parser_log -w web_logs.log")
    print("If a log type is not especified it is assumed a web log")
    print("example 2:parser_log web_logs.log")
    print("example 3:python parser_logs.py -w web-server.log -r RSVP-agent-log -c client_hostname.csv ")

def create_output_dir():
    try:
        os.makedirs(OUTPUT_FP)
    except:
        return

def pretty(d, indent=0):
    for key, value in d.items():
        print('\t' * indent + str(key))
        if isinstance(value, dict):
            pretty(value, indent+1)
        else:
            print('\t' * (indent+1) + str(value))

# Función para leer y parsear el archivo access.log
def parse_access_log(file_path):
    with open(file_path, 'r') as archivo:
        count = 0
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        m = {}
        for line in archivo:
            count += 1
            month_year = line[line.find("[")+4:line.find("]")-15]
            type = line[line.find("\"")+1:line.find(" ",line.find("\""))].strip()
            pos_inic_recurso = line.find("/", line.find("\""))+1
            pos_fin_recurso = line.find("/", pos_inic_recurso)
            recurso = line[pos_inic_recurso:pos_fin_recurso]
            if recurso[:recurso.find("?")] == "filter":
                recurso = "filter"
            if recurso[:recurso.find("?")] == "search":
                recurso = "search"
            if recurso[:recurso.find("?")] == "ajaxFilter":
                recurso = "ajaxFilter"    
            
            ip = line[:line.find("-")].strip()

            if ip in m:
                if type in m[ip]:
                    m[ip][type] += 1
                else:
                    m[ip][type] = 1

                if recurso in m[ip]:
                    m[ip][recurso] += 1
                else:
                    m[ip][recurso] = 1
                
                if month_year in m[ip]:
                    m[ip][month_year] += 1
                else:
                    m[ip][month_year] = 1 
            else:
                m[ip] = {}
                m[ip][type] = 1
                m[ip][recurso] = 1
                m[ip][month_year] = 1

            if count == MAX_COUNT:
                break

    return m




def group_csv_info(data):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    control = con.ControlPrograma()
    count = 0
    p = {}

    #Hacemos un ciclo sobre cada linea de la variable data
    for line in data:
        count   += 1
        ip       = line[0]
        hostname = line[1]
        ip_host  = ip.replace(".", "-")

        control.setIp(ip)
        tipo                = control.tipo()
        clase               = "Clase " + control.clase()

        if ip==hostname:
            hostname = "Mismo Hostname que IP ([Errno 1] Unknown host)"
        if ip_host in hostname:
            hostname = hostname[hostname.find(".")+1:]
        if ip in hostname: 
            hostname = hostname[re.search(pattern, hostname).end()+1:]


        if hostname in p:
            p[hostname]["total"] += 1
            if tipo in p[hostname]["Rangos de direcciones"]:
                p[hostname]["Rangos de direcciones"][tipo] += 1
            else:
                p[hostname]["Rangos de direcciones"][tipo] = 1

            if clase in p[hostname]["Rangos de direcciones"]:
                p[hostname]["Rangos de direcciones"][clase] += 1
            else:
                p[hostname]["Rangos de direcciones"][clase] = 1
        else:
            p[hostname] = {}
            p[hostname]["Rangos de direcciones"] = {}
            p[hostname]["Rangos de direcciones"][tipo] = 1
            p[hostname]["Rangos de direcciones"][clase] = 1
            p[hostname]["total"] = 1

        if count == MAX_COUNT:
            break
    #pretty(dict(sorted(p.items(), reverse=True, key=lambda item: item[1]['total'])))
    return dict(sorted(p.items(), reverse=True, key=lambda item: item[1]['total']))

# Función para leer y parsear el archivo RSVP-agent-log
def parse_rsvp_agent_log(file_path):
    with open(file_path, 'r') as file:
        logs = []
        for line in file:
            logs.append(line.strip())
    return logs

# Función para leer y parsear el archivo web-server.log
def parse_web_server_log(file_path):
    with open(file_path, 'r') as file:
        logs = []
        for line in file:
            if "Alert" in line:
                logs.append({"Type": "Alert", "Content": line.strip()})
            elif "Rule" in line:
                logs.append({"Type": "Rule", "Content": line.strip()})
            elif "Src IP" in line:
                logs.append({"Type": "Src IP", "Content": line.strip()})
            elif re.match(r'\d{4} \w{3} \d{2}', line):
                logs.append({"Type": "Timestamp", "Content": line.strip()})
    return logs

# Función para leer y parsear el archivo client_hostname.csv
def parse_client_hostname_csv(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        headers = next(reader)
        data = [row for row in reader]
    return headers, data


# Guardar los resultados de la agrupacion de access.log en un archivo CSV
def save_to_csv(data, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Category', 'Count'])
        for ip, details in data.items():
            for key, value in details.items():
                writer.writerow([ip, key, value])

# Guardar los resultados de client_hostname en un archivo CSV
def save_client_hostname_to_csv(data, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Host', 'Tipo de IP', 'Conteo'])
        for ip, details in data.items():
            for key, value in details.items():
                if isinstance(value, dict):
                    for key, value in value.items():
                        writer.writerow([ip, key, value])
                else:
                    writer.writerow([ip, key, value])


# Contar la frecuencia de IPs en los registros del access log
def count_ip_frequencies(data):
    ip_counts = {}
    for ip in data:
        ip_counts[ip] = sum(data[ip].values())
    return ip_counts


# Guardar las frecuencias de IP en un archivo CSV
def save_ip_counts_to_csv(ip_counts, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Count'])
        for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])


# Generar un gráfico de las IPs más comunes en el access log (sin usar matplotlib)
def generate_top_ips_graph(ip_counts, file_path):
    top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    with open(file_path, 'w') as f:
        f.write("Top 10 IPs by Request Count\n")
        f.write("IP Address\tNumber of Requests\n")
        for ip, count in top_ips:
            f.write(f"{ip}\t{count}\n")

#Maneja especificamente los logs de acceso
def handle_access_logs(file_path):
    parsed_log = parse_access_log(file_path)

    ip_counts = count_ip_frequencies(parsed_log)
    save_ip_counts_to_csv(ip_counts, os.path.join(OUTPUT_FP,'ip_counts.csv'))
    generate_top_ips_graph(ip_counts, os.path.join(OUTPUT_FP,'top_10_ips_access_log.txt'))

    save_to_csv(parsed_log, os.path.join(OUTPUT_FP,'parsed_access_log.csv'))
    # Mostrar los resultados en la terminal
    pretty(parsed_log)

#maneja los logs de rsvp    
def handle_rsvp_logs(file_path):
    parsed_log = parse_rsvp_agent_log(file_path)

    # Guardar el log de RSVP-agent-log en un archivo de texto
    output_fp = os.path.join(OUTPUT_FP,'parsed_rsvp_agent_log.txt')
    with open(output_fp, 'w') as f:
        for line in parsed_log:
            f.write(line + '\n')

    logging.info("* Parsed info written to {}*".format(output_fp))

#maneja los logs web
def handle_web_logs(file_path):
    parsed_log = parse_web_server_log(file_path)

    # Guardar el log de web-server.log en un archivo de texto
    output_fp = os.path.join(OUTPUT_FP,'parsed_web_server_log.txt')
    with open(output_fp, 'w') as f:
        for entry in parsed_log:
            f.write(f"{entry['Type']}: {entry['Content']}\n")

    logging.info("* Parsed info written to {}*".format(output_fp))


#maneja los logs de hosts
def handle_csv_logs(csv_fp):
    client_hostname_headers, client_hostname_data = parse_client_hostname_csv(csv_fp)
    parsed_log = group_csv_info(client_hostname_data)
    # Guardar el archivo client_hostname.csv procesado en un archivo CSV
    output_fp = os.path.join(OUTPUT_FP,'parsed_client_hostname.csv')
    save_client_hostname_to_csv(parsed_log, output_fp)
    logging.info("* Parsed info written to {}*".format(output_fp))

def main(csv_log_fp,web_log_fp,rsvp_fp,access_fp):

    create_output_dir()

    if access_fp:
        logging.info("* Working with {} *".format(access_fp))
        handle_access_logs(access_fp)
    if rsvp_fp:
        logging.info("* Working with {} *".format(rsvp_fp))
        handle_rsvp_logs(rsvp_fp)
    if web_log_fp:
        logging.info("* Working with {} *".format(web_log_fp))
        handle_web_logs(web_log_fp)
    if csv_log_fp:
        logging.info("* Working with {} *".format(csv_log_fp))
        handle_csv_logs(csv_log_fp)





if __name__ == '__main__':
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,datefmt="%I:%M:%S %p")

    if len(sys.argv) < 2:
        print_how_to_use()
        exit(1)

    p_args = ProgramArgs(sys.argv)
    p_args.check_args()

    main(p_args.csv_log_fp,p_args.web_log_fp,p_args.rsvp_fp,p_args.access_fp)