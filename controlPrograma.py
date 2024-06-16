# Description: Clase que controla el programa
# Autor: Kevao dv
class ControlPrograma:

    # constructor
    def __init__(self):
        self.ip = ""

    # obtener la ip
    def getIp(self):
        return self.ip

    # asignar una ip
    def setIp(self, ip):
        self.ip = ip

    # separar una ip por secciones
    def separar(self):
        ip = self.getIp()
        ip = ip.split(".")
        return ip

    # validar que la ip sea correcta
    def validar(self):
        ip = self.separar()
        if len(ip) != 4:
            return False
        for i in ip:
            if int(i) < 0 or int(i) > 255:
                return False
        return True

    # obtener la clase de la ip
    def clase(self):

        if self.validar():

            ip = self.separar()

            if (int(ip[0]) > 240):
                return "E"

            elif (int(ip[0]) >= 224):
                return "D"

            elif (int(ip[0]) >= 192):
                return "C"

            elif (int(ip[0]) >= 128):
                return "B"

            elif (int(ip[0]) >= 0):
                return "A"
        else:
            return "La ip no es valida"

    # obtener el tipo de ip
    def tipo(self):
        if self.validar():

            ip = self.separar()

            p1 = int(ip[0]) == 10

            p2 = int(ip[0]) == 172 and (int(ip[1]) >= 16 and int(ip[1]) <= 31)

            p3 = int(ip[0]) == 192 and int(ip[1]) == 168

            r1 = int(ip[0]) == 127

            r2 = int(ip[0]) == 0 and int(ip[1]) == 0 and int(ip[2]) == 0 and int(ip[3]) == 0

            r3 = int(ip[0]) == 169 and int(ip[1]) == 254

            if p1 or p2 or p3:
                return "PRIVADA"
            elif r1 or r2 or r3:
                return "RESIDENCIAL"
            else:
                return "PUBLICA"
        else:
            return "La ip no es valida"

    # comparador de clase
    def comparador(self, clase):
        if self.validar():
            if self.clase() == clase:
                return True
            else:
                return False
        else:
            return False

    # estructura de la ip
    def estructura(self):
        if self.validar():
            if self.comparador("C") or self.comparador("D") or self.comparador("E"):
                return "N.N.N.H"
            elif self.comparador("B"):
                return "N.N.H.H"
            elif self.comparador("A"):
                return "N.H.H.H"

    # direccion de red
    def direccion_red(self):
        if self.validar():
            ip = self.separar()
            if self.comparador("C") or self.comparador("D") or self.comparador("E"):
                return ip[0] + "." + ip[1] + "." + ip[2] + ".0"
            elif self.comparador("B"):
                return ip[0] + "." + ip[1] + ".0.0"
            elif self.comparador("A"):
                return ip[0] + ".0.0.0"

    # direccion de broadcast
    def drireccion_broadcast(self):
        if self.validar():
            ip = self.separar()
            if self.comparador("C") or self.comparador("D") or self.comparador("E"):
                return ip[0] + "." + ip[1] + "." + ip[2] + ".255"
            elif self.comparador("B"):
                return ip[0] + "." + ip[1] + ".255.255"
            elif self.comparador("A"):
                return ip[0] + ".255.255.255"

    # mascara x defecto
    def mascara_defecto(self):
        if self.validar():
            if self.comparador("C") or self.comparador("D") or self.comparador("E"):
                return "255.255.255.0"
            elif self.comparador("B"):
                return "255.255.0.0"
            elif self.comparador("A"):
                return "255.0.0.0"

    #direccion de host's
    def direccion_host(self):
        if self.validar():
            ip = self.separar()
            if self.comparador("C") or self.comparador("D") or self.comparador("E"):
                return "0.0.0." + ip[3]
            elif self.comparador("B"):
                return "0.0." + ip[2] + "." + ip[3]
            elif self.comparador("A"):
                return "0." + ip[1] + "." + ip[2] + "." + ip[3]

    def __str__(self):
        if self.validar():
            return "Ip: " + self.getIp() + "\nClase: " + self.clase() + "\nTipo: " + self.tipo() + "\nEstructura: " + self.estructura() + "\nDireccion de red: " + self.direccion_red() + "\nDireccion de broadcast: " + self.drireccion_broadcast() + "\nMascara por defecto: " + self.mascara_defecto() + "\nDireccion de host: " + self.direccion_host()
        else:
            return "La "+self.getIp()+" ip no es valida"

    def to_array(self):
        if self.validar():
            return [self.getIp(), self.clase(), self.tipo(), self.estructura(), self.direccion_red(), self.drireccion_broadcast(), self.mascara_defecto(), self.direccion_host()]
        else:
            return [self.getIp()]