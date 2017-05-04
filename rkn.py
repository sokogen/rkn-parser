#!../bin/python
# -*- coding: utf-8 -*-
# Скрипт считывает .xml файл от Роскомнадзора и настраивает роутер и прокси-сервер
# для реализации соответствующих блокировок.

# Default modules
import configparser ,operator ,os, sys ,string, argparse
from urllib import parse
from ipaddress import IPv4Interface
import xml.etree.ElementTree as ET

# Переходим в директорию скрипта
os.chdir(os.path.dirname(sys.argv[0]))

try:
	config = configparser.ConfigParser()
	config.read('rkn.cfg')
	# Считываем значения по умолчанию
	dumpfile = config.get('general','xmlfile')
	nodetype = config.get('general','nodetype')
except:
	print ("Can`t read config from 'rkn.cfg'")

class RknFileParser:
	"""	Класс занимается парсингом файлов .xml, полученных от Роскомнадзора """
	blockdict={'ipblock':[],										# for Iptables
	'ipfilter':[], 'ipsubnetfilter':[],								# for Iptables
	'sslipfilter':[], 'sslipsubnetfilter':[],						# for Iptables
	'domainblock':[], 'domainmaskblock':[],							# for Squid
	'domainfilter':[],'urlblock':[],								# for Squid
	'ssldomainfilter':[], 'sslurlblock':[] }						# for Squid

	def __init__(self):
		pass

	def Parser(self, dumpfile=dumpfile):
		""" Парсим файл и заполняем основной словарь блокировок """
		# Получаем сырые данные из xml файла
		raw_content = ET.parse(dumpfile).getroot().findall("content")
		# Сепарируем данные
		for c in raw_content:
			if c.get('blockType') == "domain": self.add_domainblock(c)
			elif c.get('blockType') == "domain-mask": self.add_domainmaskblock(c)
			elif c.get('blockType') == "ip": self.add_ipblock(c)
			elif c.get('blockType') == "ipSubnet": self.add_ipSubnetfilter(c)
			elif 'blockType' not in c.attrib: self.add_generalblock(c)
			else: print ("WARNING: Changed file format. New type of block detected.", content.attrib)
		
		#print(self.blockdict['urlblock'])

	def add_domainblock(self, content):
		""" Добавляем записи блокировки по домену """
		self.blockdict['ipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
		self.blockdict['sslipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
		self.blockdict['domainblock'].extend(map(lambda domain: domain.text.encode('idna').decode('utf-8'), content.findall('domain')))

	def add_domainmaskblock(self, content):
		""" Добавляем записи блокировки по доменной маске """
		self.blockdict['ipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
		self.blockdict['sslipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
		self.blockdict['domainmaskblock'].extend(map(lambda domain: domain.text.encode('idna').decode('utf-8'), content.findall('domain')))

	def add_ipblock(self, content):
		""" Добавляем записи блокировки по ip-адресу """
		self.blockdict['ipblock'].extend(map(lambda ip: ip.text, content.findall('ip')))

	def add_ipSubnetfilter(self, content):
		""" (WARNING: function was not tested!) Добавляем записи блокировки подсетей 
		Т.к. на момент разработки не было ни одной записи этой категории, функция не тестировалась,
		возможно необходима доработка функции. """
		self.blockdict['ipsubnetfilter'].extend(map(lambda subnet: self.prepareIpSubnet(subnet.text), content.findall('ipSubnet')))
		self.blockdict['sslipsubnetfilter'].extend(map(lambda subnet: self.prepareIpSubnet(subnet.text), content.findall('ipSubnet')))

	def add_generalblock(self, content):
		""" Добавляем записи блокировки по умолчанию """
		urllist=(tuple(map(lambda url: url.text,content.findall('url'))))
		for url in urllist:
			url = self.prepareUrl(url)
			if url.scheme == 'https':
				self.blockdict['ssldomainfilter'].append(url.netloc)
				self.blockdict['sslurlblock'].append(url.geturl())
				self.blockdict['sslipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
			elif url.scheme is 'http' or 'newcamd525':
				# Нет необходимости собирать домены http, когда можно проверять сразу URL
				#self.blockdict['domainfilter'].append(url.netloc)
				self.blockdict['urlblock'].append(url.geturl())
				self.blockdict['ipfilter'].extend(map(lambda ip: ip.text, content.findall('ip')))
			else:
				print("Unknown URL scheme:", url.geturl())
				print(content.attrib, '\n')

	def prepareUrl(self, url):
		""" Конвертируем национальные домены """
		url = parse.urlparse(url)
		url = url._replace(netloc=str(url.netloc.encode('idna').decode('utf-8')))
		return url

	def prepareIpSubnet(self, subnet):
		""" Форматируем подсеть под формат Cisco ACL """
		return ' '.join(IPv4Interface(subnet).with_hostmask.split('/'))

	def getStat(self, dumpfile=dumpfile):
		""" Выводит статистику по атрибутам контента и их количеству.
		Измеряются атибуты: 'entryType', 'blockType', 'urgencyType' """
		self.sd={'entryType':{}, 'blockType':{}, 'urgencyType':{}}

		# Получаем "сырые" данные из xml файла
		raw_content = ET.parse(dumpfile).getroot().findall("content")

		# Собираем данные о количестве контентов по атрибутам
		for c in raw_content: 
			for t in self.sd.keys():
				if t in c.attrib: self.sd[t][c.get(t)] = self.sd[t].get(c.get(t), 0) + 1
				else: self.sd[t][None] = self.sd[t].get(None, 0) + 1

		# Выводим полученные данные
		print ("All records count:", len(raw_content))		
		for d in sorted(self.sd.keys()):
			print (d+":")
			for t in self.sd[d]:
				print ("Type '"+str(t)+"' count:", self.sd[d][t])

	def FileGen(self, dumpfile=dumpfile):
		""" Генерируем файлы конфигурации для Squid из словаря блокировок, заполненного парсером.
		В результате работы получаем набор файлов в указанном каталоге. """
		# Проверяем, заполнен ли словарь, если нужно: заполняем.
		if len(self.blockdict['ipfilter']) < 1: self.Parser(dumpfile)
		squid_output_dir = config.get('general','squid_output_dir')
		# Проверяем наличие директории для файлов, при необходимости создаем
		if not os.path.exists(squid_output_dir): os.makedirs(squid_output_dir)
		# Ограничиваем набор файлов для конкретного типа ноды
		if args.nodetype == 'http':
			squidfiles = ('domainblock', 'domainmaskblock', 'urlblock')
			ipdicts = ('ipblock', 'ipfilter', 'ipsubnetfilter')
			dport=80
			squidport=config.get('squid','http_port')
		elif args.nodetype == 'https':
			squidfiles = ( 'domainblock', 'domainmaskblock', 'ssldomainfilter', 'sslurlblock')
			ipdicts = ('ipblock', 'sslipfilter', 'sslipsubnetfilter')
			dport=443
			squidport=config.get('squid','https_port')
		else: files = self.blockdict.keys()

		for file in squidfiles:
			# Открываем файл на запись и очищаем его
			trgtfile = open(os.path.join(squid_output_dir, file), 'w')
			trgtfile.truncate()
			if file in ('domainblock', 'domainfilter', 'ssldomainfilter'):
				command = ".{}\n"
			elif file in ('domainmaskblock'):
				command = "{}$\n"
			elif file in ('urlblock', 'sslurlblock'):
				command = "^{}$\n"

			for rec in self.blockdict[file]:
				trgtfile.write(command.format(rec))
			trgtfile.close()

		# Открываем и очищаем файлы для правил iptables
		trgtfile = open(config.get('fw','ip_output_file'), 'w')
		trgtfile.truncate()
		rules={'drop':[], 'redirect':[]}

		# Генерируем команды для iptables-restore, убираем дублирующиеся записи
		for ipdict in ipdicts:
			if ipdict in ('ipfilter', 'sslipfilter', 'ipsubnetfilter', 'sslipsubnetfilter'):
				iplist = list(set(self.blockdict[ipdict]))
				command = "-A PREROUTING -d {} -p tcp -m tcp --dport {} -j REDIRECT --to-ports {}"
				for rec in iplist:
					rules['redirect'].append(command.format(rec,dport,squidport))
			elif ipdict in ('ipblock'):
				iplist = list(set(self.blockdict[ipdict]))
				command = "-A INPUT -d {} -p tcp -m tcp --dport {} -j DROP"
				for rec in iplist:
					rules['drop'].append(command.format(rec,dport))

		# Считываем шаблон и записываем правила в файл для iptables-restore
		tempfile = open(config.get('fw','template'))
		template = ''.join(tempfile.readlines())
		trgtfile.write(template.format(drop_rules='\n'.join(rules['drop']), redirect_rules='\n'.join(rules['redirect'])))
		trgtfile.close()

def get_args():
	"""Собираем переданные аргументы из консоли"""
	parser = argparse.ArgumentParser(
		description='''Скрипт формирует файлы для фильтрации запрещенного трафика с помощью сервера squid.''',
		epilog='''
		На текущий момент не реализована поддержка выгрузки регистра с сайта Роскомнадзора.
		Информация берется из файла dump.xml. ''')

	parser.add_argument('-i', '--stat',
						action='store_true', required=False,
						help='show dump statistic')

	parser.add_argument('-t', '--type', '--nodetype', dest='nodetype',
						action='store', choices=['http', 'https'],
						default='https',
						help='Select type of node: http, https (default https)')

	parser.add_argument('-d', '--dump',
						dest='dumpfile', metavar="dir/dump/file",
						required=False, action='store',
						help='Dump file (default in rkn.cfg)')

	args = parser.parse_args()
	if len(str(args.dumpfile)) > 0 : dumpfile = args.dumpfile
	if len(str(args.nodetype)) > 0 : nodetype = args.nodetype
	return args

if __name__ == '__main__':
	args = get_args()
	rkn = RknFileParser()
	if args.stat == True: rkn.getStat(dumpfile)
	rkn.FileGen()