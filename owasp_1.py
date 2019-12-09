# coding: utf8
import requests
import selenium
import sys
import os
import time
import subprocess
import socket
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from pyfiglet import Figlet
from termcolor import colored
import urllib3
from selenium.webdriver.firefox.options import Options
from fpdf import FPDF

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)	

global url2
global cross
global client
def rela():	
	pdf = FPDF()
	pdf.add_font('DejaVu', '', '/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf', uni=True)
	print "\n-----------------------------------------------------------------------------"
	print "[+] TESTES REALIZADOS"
	print (colored("[!] Testes que necessitam de interpretação de output não são definidos como vulneráveis ou não vulneráveis.",'yellow'))
	print "Gerando relatório..."
	pdf.add_page()
	pdf.set_fill_color(192,192,192)
	pdf.set_draw_color(0,0,0)
	pdf.set_text_color(255,255,255)
	pdf.rect(0,0, 500, 500, 'DF')
	pdf.set_fill_color(128,128,128)
	pdf.ln()
	pdf.set_font('DejaVu','',60)
	pdf.cell(120, 20 ,"OWASP v1",fill=True)
	pdf.set_font('DejaVu','', 20)
	pdf.ln()
	pdf.cell(120, 10 ,"Relatório de Vulnerabilidades",fill=True)
	pdf.ln()
	pdf.cell(120 ,10 ,"Data: "+time.ctime(),fill=True)
	pdf.set_font('DejaVu', '', 20)
	pdf.ln()
	try:
		pdf.cell(120, 10 ,"IP:"+ip,fill=True)
	except:
		pass
	pdf.ln()
	pdf.cell(120, 10 ,"URL: "+url,fill=True)
	pdf.ln(15)
	pdf.set_font('DejaVu','',13)
	autores = ['Estevão Ferreira','Lucas Antoniaci','Marcelo Expedito','Winicius Pousada']
	pdf.set_text_color(255,255,255)
	pdf.cell(60,10,'AUTORES:',align='C',fill=True)
	pdf.ln()
	for k in autores:
		pdf.cell(60,10,k,align='C',fill=True)
		pdf.ln()
	pdf.set_font('DejaVu', '', 20)
	pdf.add_page()
	pdf.set_text_color(255,255,255)
	pdf.set_fill_color(0,0,0)
	pdf.cell(190,10,"TESTES",align='C',fill=True)
	pdf.ln(20)
	pdf.set_fill_color(164,164,164)
	pdf.set_text_color(0,0,0)
	for x in otgfeitos:
		pdf.cell(190, 10,"- "+x,fill=True)
		pdf.ln()
	#pdf.image('grafico.png')
	if "INFORMATION GATHERING" in tsfeitos:
		pdf.add_page()
		pdf.set_text_color(255,255,255)
		pdf.set_fill_color(0,0,0)
		pdf.cell(190,10,"INFORMATION GATHERING",align='C',fill=True)
		pdf.ln(20)
		pdf.set_text_color(0,0,0)
		pdf.set_font('DejaVu', '', 20)
		pdf.set_fill_color(164,164,164)
		pdf.cell(190,10,"CAPTURA DE TELA",fill=True)
		pdf.ln()
		pdf.image(url3+'.png',w= 200, h=190)
		pdf.cell(190, 10,"INFO-001",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar informações sensíveis através de ferramentas de busca.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Obtenção de informações sensíveis sobre o host.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Conduct_search_engine_discovery/reconnaissance_for_information_leakage_(OTG-INFO-001)",fill=True)
		pdf.multi_cell(190,10,"STATUS: N/A",fill=True)
		pdf.ln()
		pdf.cell(190,10,"BUSCA EM GOOGLE E DUCKDUCKGO:",fill=True)
		pdf.ln()
		for z,d in zip(xrp,yrp):
			pdf.cell(190,10,"Titulo: "+ z,border=True)
			pdf.ln()
			pdf.cell (190,10,"URL: "+ d,border=True)
			pdf.ln(	)	
		for j,k in zip(xrp1,xrp2):
			pdf.cell(190,10,"Titulo: "+ j,border=True)
			pdf.ln()
			pdf.cell (190,10,"URL: "+ k,border=True)
			pdf.ln(	)
		pdf.ln()
		pdf.set_font('DejaVu', '', 20)
		pdf.cell(190, 10,"INFO-002",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar versão de servidor através de cabeçalho de resposta.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Identificação de versão de servidor, permitindo a execução de exploits contra a versão descoberta.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002)",fill=True)
		pdf.multi_cell(190,10,"STATUS: N/A",fill=True)
		pdf.ln()
		pdf.cell (190,10,"BANNER DE SERVIDOR:",fill=True)
		pdf.ln()
		pdf.multi_cell(190,10,banner,border=True)
		pdf.ln()
		pdf.set_font('DejaVu', '', 20)
		pdf.cell(190, 10,"INFO-003",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar vazamento de dados através de metadados.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Identificação de informações e/ou diretórios sensíveis.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Review_Webserver_Metafiles_for_Information_Leakage_(OTG-INFO-003)",fill=True)
		pdf.multi_cell(190,10,"STATUS: N/A",fill=True)
		pdf.ln()
		if robots == False:
			pdf.cell(190, 10,"ARQUIVO ROBOTS NÃO IDENTIFICADO",fill=True)
			pdf.ln()	
		elif robots == True:
			pdf.cell(190, 10,"ARQUIVO ROBOTS.TXT IDENTIFICADO:",fill=True)
			pdf.ln()
			pdf.image('robots.png',w= 100, h=80)
			pdf.ln()
		pdf.set_font('DejaVu', '', 20)
		pdf.ln()
		pdf.cell(190, 10,"INFO-004",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar serviços de host.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Possibilidade de constatação de serviço vulnerável.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Enumerate_Applications_on_Webserver_(OTG-INFO-004)",fill=True)
		pdf.multi_cell(190,10,"STATUS: N/A",fill=True)
		pdf.ln()
		pdf.multi_cell(190,10,"SCAN NMAP",fill=True)
		pdf.set_font('DejaVu', '', 6)
		pdf.multi_cell(190, 10,output,border=True)
	if "CONFIGURATION AND DEPLOY MANAGEMENT TESTING" in tsfeitos:
		pdf.add_page()
		pdf.set_font('DejaVu','',20)
		pdf.set_text_color(255,255,255)
		pdf.set_fill_color(0,0,0)
		pdf.cell(190,10,"CONFIGURATION AND DEPLOY MANAGEMENT TESTING",align='C',fill=True)
		pdf.ln()
		pdf.set_fill_color(164,164,164)
		pdf.set_text_color(0,0,0)
		pdf.cell(190, 10,"CONFIG-005",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar interfaces administrativas expostas.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Possibilidade de acesso a página de login administrativa.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Enumerate_Infrastructure_and_Application_Admin_Interfaces_(OTG-CONFIG-005)",fill=True)
		pdf.set_font('DejaVu', '', 10)
		if len(diret) > 0:
			pdf.set_fill_color(255,0,0)
			pdf.multi_cell(190,10,"STATUS: VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
 			pdf.cell(190,10,str(len(diret))+" diretórios descobertos:",fill=True)
			pdf.ln()
			for k in diret:
				pdf.multi_cell(190,10,str(diret),border=True)
				pdf.ln()
		elif len(diret) == 0:
			pdf.set_fill_color(0,255,0)
			pdf.multi_cell(190,10,"STATUS: NÃO VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
			pdf.cell(190,10,"Não foram descobertos diretórios.",fill=True)
		elif len(diret) == 42:
			pdf.set_fill_color(255,0,0)
			pdf.multi_cell(190,10,"STATUS: VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.cell(190,10,str(len(diret))+" diretórios descobertos",fill=True)
			pdf.ln()
			pdf.cell(190,10,"Possívelmente falso positivo",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',20)
		pdf.cell(190, 10,"CONFIG-006",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar uso de métodos HTTP maliciosos.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Possibilidade de uso de método HTTP para bypass ou comprometimento de outros ativos.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)",fill=True)
		pdf.set_font('DejaVu', '', 10)
		pdf.multi_cell(190,10,"SCAN NMAP",fill=True)
		pdf.set_font('DejaVu', '', 6)
		pdf.multi_cell(190, 10,output1,border=True)
		pdf.set_font('DejaVu','',20)
		pdf.ln()
		pdf.cell(190,10,"CONFIG-007",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Verificar uso de cabeçalho Strict-Transport-Security.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Possibilidade de uso de conexão HTTP compromentendo confidencialidade de dados sensíveis.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Test_HTTP_Strict_Transport_Security_(OTG-CONFIG-007)",fill=True)
		if strict == True:
			pdf.set_fill_color(255,0,0)
			pdf.multi_cell(190,10,"STATUS: VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
			pdf.set_text_color(0,0,0)
			pdf.cell(190,10,"Ausência de cabeçalho Strict-Transport-Security!",fill=True)
		elif strict == False:
			pdf.set_fill_color(0,255,0)
			pdf.multi_cell(190,10,"STATUS: NÃO VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
			pdf.cell(190,10,"Cabeçalho Strict-Transport-Security habilitado!", fill=True)
		pdf.ln()
		pdf.ln()
		pdf.set_font('DejaVu','',20)
		pdf.cell(190,10,"(CONFIG-008)",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar política de domínio exposta.",fill=True)
		pdf.multi_cell(190,10,"Impacto: Obter informações que podem servir de pivot para outros ataques.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_(OTG-CONFIG-008)",fill=True)
		pdf.set_font('DejaVu', '', 10)
		if cross == True:
			pdf.cell(190,10,"Arquivo de política exposto!" ,fill=True)
			pdf.ln()
			pdf.cell(190,10,'Arquivo crossdomain.xml:',fill=True)
			pdf.ln()
			pdf.image('crossdomain.png',w= 190, h=100)
			pdf.ln()
		elif client == True:
			pdf.cell(190,10,"Arquivo de política exposto!",fill=True)
			pdf.ln()
			pdf.cell(190,10,'Arquivo clientaccesspolicy.xml:',fill=True)
			pdf.image('clientaccess.png',w= 190, h=100)
			pdf.ln()
		else:
			pdf.cell(190,10,"Não foram identificados arquivos de política expostos.",fill=True)
			pdf.ln()
	if "AUTHORIZATION TESTING" in tsfeitos:
		pdf.add_page()
		pdf.set_text_color(255,255,255)
		pdf.set_fill_color(0,0,0)
		pdf.cell(190,10,"AUTHORIZATION TESTING",align='C',fill=True)
		pdf.ln(20)
		pdf.set_text_color(0,0,0)
		pdf.set_font('DejaVu', '', 20)
		pdf.set_fill_color(164,164,164)
		pdf.cell(190, 10,"AUTHZ-001",fill=True)
		pdf.ln()
		pdf.set_font('DejaVu','',8)
		pdf.multi_cell(190,10,"Objetivo: Identificar existência de vulnerabilidade Directory Traversal(LFI).",fill=True)
		pdf.multi_cell(190,10,"Impacto: Visualização não autorizada de arquivos locais de host.",fill=True)
		pdf.multi_cell(190,10,"Referência: https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)",fill=True)
		pdf.set_font('DejaVu','',10)
		if lfi == True:
			pdf.set_fill_color(255,0,0)
			pdf.multi_cell(190,10,"STATUS: VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
			pdf.cell(190,10,"ARQUIVO PASSWD:",fill=True)
			pdf.ln()
			pdf.cell(190,10,lfir,border=True)
		else:
			pdf.set_fill_color(0,255,0)
			pdf.multi_cell(190,10,"STATUS: NÃO VULNERÁVEL",fill=True)
			pdf.ln()
			pdf.set_fill_color(164,164,164)
	pdf.output('OWASP_'+url3+'.pdf', 'F')
	print "Relatório gerado: OWASP_"+url3+".pdf"

def fim():
	print (colored("Verifique os parâmetros e tente novamente!",'red'))
def authz():
	global tsfeitos
	global lfi
	global lfir
	lfi = False
	print ("| AUTHORIZATION TESTING |\n")
	print ("(AUTHZ-001) Identificar Directory Traversal/File Include:\n")
	teste = '/../../etc/passwd'
	murl = url+teste
	print "     [-] - GET "+murl
	try:
		req1 = requests.get(url=murl, timeout=60)
		if req1.status_code == 200:
			print "     [+] "+ murl + " [200]"
		if ('root' in req1.content) == True:
			print "     [!] LFI encontrado!"
			print "RESPOSTA:\n"
			print req1.content
			lfir = req1.content
			lfi = True
		elif req1.status_code == 404:
			print "     [-] "+ murl + " [404]\n"
		elif req1.status_code == 403:
			print "     [-] "+ murl + " [403]\n"
			print "--------------------------"
	except:
		print "     [-] "+ murl + " [ERRO]\n"
		print "--------------------------"
	tsfeitos.append("AUTHORIZATION TESTING")
	otgfeitos.append('AUTHZ-001')
	rela()
def conf():
	global des2
	global conf
	global tsfeitos
	global diret
	global strict
	global cross
	global client
	global crossdomain
	global clientaccesspolicy
	global output1
	poli = []
	diret = []
	conf = 0
	cross = False
	client = False
	print ("| CONFIGURATION AND DEPLOY MANAGEMENT TESTING |\n")
	print ("(CONFIG-005) Identificar interfaces administrativas:\n")
	lista = ['admin','admin-authz.xml','admin.conf','admin.passwd','admin/*','admin/logon.jsp','admin/secure/logon.jsp','phpinfo','phpmyadmin/','phpMyAdmin/','mysqladmin/','MySQLadmin','MySQLAdmin','login.php','logon.php','xmlrpc.php','dbadmin','admin.dll','admin.exe','administrators.pwd','author.dll','author.exe','author.log','authors.pwd','cgi-bin','AdminCaptureRootCA','AdminClients','AdminConnections','AdminEvents','AdminJDBC','AdminLicense','AdminMain','AdminProps','AdminRealm','AdminThreads','wp-admin/','wp-admin/about.php','wp-admin/admin-ajax.php','wp-admin/admin-db.php','wp-admin/admin-footer.php','wp-admin/admin-functions.php','wp-admin/admin-header.php']
	for x in lista:
		url1 = url +'/' + x
		try:
			req1 = requests.get(url1,verify=False)
		except:
			print (colored(" [!] Erro em comunicação:", 'yellow')), url1
		if req1.status_code == 200:
			print (colored( " [+] Diretório descoberto:", 'green')), url1, "[",req1.status_code,"]"
			diret.append(url1)
		elif req1.status_code == 404:
			print (colored( " [-] Diretório inexistente:", 'red')),url1, "[",req1.status_code,"]"
		elif req1.status_code == 403:
			print (colored( " [-] Diretório com acesso negado:", 'yellow')),url1, "[",req1.status_code,"]"
	print len(diret)," diretório(s) descoberto(s)."
	if len(diret) == 42:
		print (colored("(!) Possivelmente falso positivo.",'yellow'))
	elif len(diret) > 0 < 42:
		conf += 1
	print "\n-----------------------------------------------------------------------------"
	print ("(CONFIG-006) Identificar métodos HTTP habilitados:\n")
	output1 = subprocess.check_output("nmap -Pn -p80,443 --script http-methods " +  url3, shell=True)
	print output1
	#os.system('nmap -Pn -p80,443 --script http-methods ' +  url3)
	print "\n-----------------------------------------------------------------------------"
	print ("(CONFIG-007) Verificar uso de Strict-Transport-Security:\n")
	req2 = requests.get(url,verify=False)
	h1 = req2.headers.get('Strict-Transport-Security')
	if h1 == None :
		print (colored ("	[!] Ausência de cabeçalho Strict-Transpor-Security !", 'red'))
		conf += 1
		strict = True
	else:
		print (colored ("	[+] Cabeçalho Strict-Transport-Security habilitado !", 'green'))
	print "\n-----------------------------------------------------------------------------"
	print ("(CONFIG-008) Identificar política de domínio exposta:\n")
	lista = ['crossdomain.xml','clientaccesspolicy.xml']
	for x in lista:
		url1 = url +'/' + x
		req3 = requests.get(url1,verify=False)
		if req3.status_code == 200:
			print (colored( " [+] Arquivo de política exposto:", 'red')), url1, "[",req3.status_code,"]\n"
			print req3.content,"\n"
			conf += 1
			poli.append(url1)
			if 'crossdomain' in url1:
				crossdomain = req3.content
				cross = True
				nav.get(url1)
				nav.save_screenshot("crossdomain.png")
			elif 'clientaccess' in url1:
				clientaccess = req3.content
				client = True
				nav.get(url1)
				nav.save_screenshot("clientacess.png")
		elif req3.status_code == 404:
			print (colored( " [-] Arquivo de política inexistente:", 'green')),url1, "[",req3.status_code,"]"
		elif req3.status_code == 403:
			print (colored( " [-] Arquivo de política com acesso negado:", 'yellow')),url1, "[",req3.status_code,"]"
	print "\n-----------------------------------------------------------------------------"
	tsfeitos.append("CONFIGURATION AND DEPLOY MANAGEMENT TESTING")
	otgfeitos.append('CONFIG-005')
	otgfeitos.append('CONFIG-006')
	otgfeitos.append('CONFIG-007')
	otgfeitos.append('CONFIG-008')
	nav.quit()
	if tudo == True:
		authz()
	else:
		rela()
def info():
	global resul1
	global link1
	global resul2
	global xrp
	global yrp
	global xrp1
	global xrp2
	global banner
	global robots
	global output
	robots = False
	xrp = []
	yrp = []
	xrp1 = []
	xrp2 = []
	fig1 = Figlet(font='doom')
	print (fig1.renderText('OWASP v1'))
	print ("| INFORMATION GATHERING |")
	try:
		nav.get(url)
		nav.save_screenshot(url3+".png")
		print "Sucesso em acesso a URL!"
	except:
		pass
		print "Não foi possível obter uma captura de tela!"
	print "|\n|  Captura de tela de URL!"
	print ("(INFO-001) Pesquisa pela internet:\n")
	nav.get('https://www.google.com/')
	time.sleep(5)
	campo1 = nav.find_element_by_xpath('/html/body/div/div[4]/form/div[2]/div[1]/div[1]/div/div[2]/input')
	campo1.send_keys(url)
	campo1.send_keys(Keys.RETURN)
	time.sleep(5)
	resul1 = nav.find_elements_by_class_name('LC20lb')
	link1 = nav.find_elements_by_class_name('iUh30')
	print "Resultados de Google...\n"
	for x,y in zip(resul1,link1):
		if x.is_displayed():		
			print "Título: ", x.text
			print "URL: ", y.text
			xrp.append(x.text)
			yrp.append(y.text)
			print "------------------------------------"
	print "\n"
	nav.get('https://duckduckgo.com/')
	campo2 = nav.find_element_by_id('search_form_input_homepage')
	campo2.send_keys(url)
	campo2.send_keys(Keys.RETURN)
	time.sleep(5)
	resul2 = nav.find_elements_by_class_name('result__a')
	print "Resultados de DuckDuckGo...\n"
	for x in resul2:
		if x.is_displayed():		
			print "Título: ", x.text
			print "URL:",x.get_attribute('href')
			xrp1.append(x.text)
			xrp2.append(x.get_attribute('href'))
			print "------------------------------------"
	print "\n"
	req1 = requests.get(url,verify=False)
	print ("(INFO-002) Banner do servidor: \n"),req1.headers.get('Server')
	banner = req1.headers.get('Server')
	print "\n-----------------------------------------------------------------------------"
	print ("(INFO-003) Arquivo robots.txt\n")
	req1 = requests.get(url=url+'/robots.txt', timeout=60,verify=False)
	if req1.status_code == 200:
		print "     [+] "+ url + "/robots.txt [200]\n"
		print req1.content
		robots = True
		nav.get(url+'/robots.txt')
		nav.save_screenshot("robots.png")
	else:
		robots = False
		print (colored( "		[-] Arquivo robots.txt não encontrado:", 'green'))
	print "\n-----------------------------------------------------------------------------"
	print ("(INFO-004) Enumerar aplicações do servidor\n")
	#os.system('nmap -Pn -sV -O ' +  url3)
	output = subprocess.check_output("nmap -Pn -sV -O " +  url3, shell=True)	
	print output
	tsfeitos.append("INFORMATION GATHERING")
	otgfeitos.append('INFO-001')
	otgfeitos.append('INFO-002')
	otgfeitos.append('INFO-003')
	otgfeitos.append('INFO-004')
	if tudo == True:
		conf()
	else:
		rela()
def menu():
	global ip
	global testes
	global tudo
	global tsfeitos
	global nav
	global otgfeitos
	options = Options()
	options.headless = True
	nav = webdriver.Firefox(options=options)
#	requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
#	try:
#		requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
#	except AttributeError:
#		pass	
	tsfeitos = []
	otgfeitos = []
	print "URL: ",url
	try:
		ip = socket.gethostbyname(url3)
		print "IP:",ip
	except:
		pass
	print "-----------------------------------------------------------------------------"
	print "Módulos disponíveis:"
	print (colored("		(1) -  Information Gathering", 'blue'))
	print 		"				+ INFO-001"
	print		"				+ INFO-002"
	print		"				+ INFO-003"
	print		"				+ INFO-004"	
	print "-----------------------------------------------------------------------------"
	print (colored("		(2) -  Configuration and Deploy Management Testing", 'blue'))
	print 		"				+ CONFIG-005"
	print		"				+ CONFIG-006"
	print		"				+ CONFIG-007"
	print		"				+ CONFIG-008"
	#print (colored("		(3) -  Identity Management Testing", 'red'))
	#print (colored("		(4) -  Authentication Testing", 'red'))
	print (colored("		(3) -  Authorization Testing", 'blue'))
	print 		"				+ AUTHZ-001"
	#print (colored("		(6) -  Session Management Testing", 'red'))
	#print (colored("		(7) -  Input Validation Testing", 'red'))
	#print (colored("		(8) -  Error Handling", 'red'))
	#print (colored("		(9) -  Criptography", 'red'))
	#print (colored("		(10) -  Client Side Testing", 'red'))
	print (colored("		(11) -  Todas opções", 'blue'))
	op = raw_input ("Selecione uma das opções: ")
	if op == '1':
		tudo = False
		info()
	elif op == '2':
		tudo = False
		conf()
	elif op == '3':
		tudo = False
		authz()
	elif op == '11':
		tudo = True
		info()
	else:
		print "Você escolheu uma opção inválida!"
try:	
	if (sys.argv[1] == '-h') or (sys.argv[1] == '-H'):
		print "-----------------------------------------------------------------------------"
		fig1 = Figlet(font='doom')
		print (fig1.renderText('OWASP v1'))
		fig2 = Figlet(font='straight')
		print (colored("By:\n  Estevão Ferreira\n  Marcelo Expedito\n  Lucas Antoniaci\n  Winicius Moreira","white"))
		print "-----------------------------------------------------------------------------"
		print "Exibir este menu de ajuda:"
		print "		python OWASP_v1.py -h/-H"
		print "Executar scan em URL:"
		print "		python OWASP_v1.py -u https://www.exemplo.com.br"
	elif (sys.argv[1] == '-u'):
		print "-----------------------------------------------------------------------------"
		url = sys.argv[2]
		if ('https://' in url) == True:
			url3 = url[8:]
			menu()
		elif ('http://' in url) == True:
			url3 = url[7:]
			menu()
		else:
			print (colored("URL inválida!",'red'))
			fim()
	else:
		print "-----------------------------------------------------------------------------"
		print (colored("Opção inválida!",'red'))
except:
	fig1 = Figlet(font='doom')
	print (fig1.renderText('OWASP v1'))
	fig2 = Figlet(font='straight')
	print (colored("By:\n  Estevão Ferreira\n  Marcelo Expedito\n  Lucas Antoniaci\n  Winicius Moreira","white"))
	print "-----------------------------------------------------------------------------"
	print ("Para exibir menu de ajuda:")
	print ("	python OWASP_v1.py -h/-H")
