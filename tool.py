#!/usr/bin/python
#-*- coding: utf-8 -*-

import sys
import struct
import os

def fchange_exist(filename):
	f = open(filename,'rb')
        f_mod = open('modified.xml','wb')
	
	find_str = finder(filename)
	find_application = struct.pack('<H',find_str['application']).encode('hex')+struct.pack('<H',0).encode('hex')
	find_debuggable = struct.pack('<H',find_str['debuggable']).encode('hex')+struct.pack('<H',0).encode('hex')

	r = f.read(4)
	f_mod.write(r)
	tmp = r.encode('hex')
	
	while True:
		r = f.read(1)
		if not r:
			break
	
		tmp = tmp[2:] + r.encode('hex')

		if tmp == '02011000':
			f_mod.write(r)
			r = f.read(32)
			tmp_stc_name = r.encode('hex')[32:40]
			tmp_ac_count = int(r.encode('hex')[54:56]+r.encode('hex')[52:54]+r.encode('hex')[50:52]+r.encode('hex')[48:50],16)
			if tmp_stc_name == find_application:
				#print "@@@"
				f_mod.write(r)
				#print tmp_ac_count
				for i in range(0,tmp_ac_count):
					#print i
					r = f.read(20)
					tmp_debuggable_name = r.encode('hex')[8:16]
					if tmp_debuggable_name == find_debuggable:
						if r.encode('hex')[16:20] != 'FFFFFFFF':
							f_mod.write(r[0:16])
							f_mod.write(struct.pack('HH',0xFFFF,0xFFFF))
							continue
						f_mod.write(r)
						continue
					f_mod.write(r)
				continue	
			f_mod.write(r)
			continue

		f_mod.write(r)


def fchange_nonexist(filename):
	f = open(filename,'rb')
	f_mod = open('modified.xml','wb')
	f_tmp = open(filename,'rb')	
	
	f_tmp_read = f_tmp.read()
	if False:'''
	str_android = ''
	str_count = 0
	str_start = 0
	last_str_address = 0
	last_str_value = 0
	find_addr = 0 	
	scSize = 0

	count = 0
	while True:
		r = f.read(2)		
		if not r:
			break
## to chage file sizee
		if count == 0x04:
			r = struct.pack('H',struct.unpack('H',r)[0] + 0x34)

## to add string chunk size ##
		if count == 0x0c:
			scSize = struct.unpack('H',r)[0]	
			r = struct.pack('H',struct.unpack('H',r)[0] + 0x1c)

## to change string count ##
		if count == 0x10:
			str_count = struct.unpack('H',r)[0]
			r = struct.pack('H',struct.unpack('H',r)[0] + 0x1)

## get string starting point ##
		if count == 0x1c:
			str_start = struct.unpack('H',r)[0]
			r = struct.pack('H',str_start + 0x4)

## to add string address ##	
		if count == 0x24+(str_count-1)*4:
			last_str_address = struct.unpack('H',r)[0]
		if count == 0x24+str_count*4:
			print last_str_address
			find_addr = last_str_address + str_start + 0x8
			last_str_value = struct.unpack('H',f_tmp_read[find_addr : find_addr+2])[0]
			print last_str_value
			addr_input = struct.pack('H',last_str_address+last_str_value*2 + 0x4)
			print addr_input.encode('hex')
			f_mod.write(addr_input)
			count += 2
			f_mod.write(struct.pack('H',0x00))
			count += 2
			f_mod.write(r)
			count += 2
			## str_count & str_start_addr changed (+0x1)	
			break		
				
		f_mod.write(r)

		count += 0x2

	while True:
		r = f.read(2)
                if not r:
                        break
## to add debuggable string ##
                if count == find_addr + 0x4 + last_str_value*2 + 0x4:
			print find_addr + 0x4 + last_str_value*2 + 0x4
                        f_mod.write(struct.pack('H',0xa))
                        for i in 'debuggable':
				f_mod.write(struct.pack('H',ord(i)))
                        f_mod.write(struct.pack('H',0x00))
			break

		
		f_mod.write(r)

                count += 0x2

	f_mod.write(r)
	'''


	find_str = finder(filename)
        find_application = struct.pack('<H',find_str['application']).encode('hex')+struct.pack('<H',0).encode('hex')
	find_allowbackup = int(find_str['allowBackup'])

## to input xml Signature ##
	r = f.read(4)
	f_mod.write(r)

## to change file size ##
	r = f.read(4)
	r = struct.pack('<L',struct.unpack('HH',r)[0] + 0x34)
	f_mod.write(r)

## to change stringPool ##
	r = f.read(28)
	f_mod.write(r[0:4])
## to change string pool size
	f_mod.write(struct.pack('<L',struct.unpack('HH',r[4:8])[0] + 0x1c))
## to change string pool count
	str_count = struct.unpack('HH',r[8:12])[0]
	f_mod.write(struct.pack('<L',struct.unpack('HH',r[8:12])[0] + 0x1))
	f_mod.write(r[12:20])
## to change string starting offset
	f_mod.write(struct.pack('<L',struct.unpack('HH',r[20:24])[0] + 0x4))
	f_mod.write(r[24:28])

## to add debuggable offset
	for i in range(0,find_allowbackup+1):
		r = f.read(4)
		f_mod.write(r)

	f_mod.write(struct.pack('<L',struct.unpack('HH',r)[0] + 0x1A))

	for i in range(find_allowbackup+1,str_count):
		r = f.read(4)
		f_mod.write(struct.pack('<L',struct.unpack('HH',r)[0] + 0x18))

## to add debuggable string
	for i in range(0,find_allowbackup+1):
		r = f.read(2)
		str_len = struct.unpack('H',r)[0]
		f_mod.write(r)
		r = f.read(str_len*2)
		#print r
		f_mod.write(r)
		r = f.read(2)
		f_mod.write(r)
	f_mod.write(struct.pack('H',0xa))
	for i in 'debuggable':
		f_mod.write(struct.pack('H',ord(i)))
	f_mod.write(struct.pack('H',0x00))
	for i in range(find_allowbackup+1,str_count):
                r = f.read(2)
                str_len = struct.unpack('H',r)[0]
                f_mod.write(r)
                r = f.read(str_len*2)
                #print r
                f_mod.write(r)
                r = f.read(2)
                f_mod.write(r)



	tmp = 'FFFF'+r.encode('hex')
## to change resource map ##
## to change namespace ##
	while True:
                r = f.read(1)
                if not r:
                        break

                tmp = tmp[2:] + r.encode('hex')
## to change resource map ##
		if tmp == '80010800':
			f_mod.write(r)
			r = f.read(4)
			rs_count = (struct.unpack('HH',r)[0]-0x8) / 4
			#print rs_count
			r =  struct.pack('HH',struct.unpack('HH',r)[0] + 0x4,0x00)
			f_mod.write(r)
			for i in range(0,rs_count):
				r = f.read(4)
				#print r.encode('hex')
				f_mod.write(r)
				if r.encode('hex') == '80020101':
					f_mod.write(struct.pack('HH',0x000F,0x0101))
			continue
## to change namespace
		if tmp == '00011000':
			f_mod.write(r)
			for i in range(0,5):
				r = f.read(4)
				if i == 3:
					r = struct.pack('H',struct.unpack('HH',r)[0] + 0x1) + struct.pack('H',0)
					#print struct.pack('H',struct.unpack('HH',r)[0] + 0x1).encode('hex')
				if i == 4:
					r = struct.pack('H',struct.unpack('HH',r)[0] + 0x1) + struct.pack('H',0)

				f_mod.write(r)
			continue
		
## to change startTagChunk ##
		if tmp == '02011000':
                        f_mod.write(r)
                        r = f.read(32)
                        tmp_stc_name = r.encode('hex')[32:40]
                        tmp_ac_count = int(r.encode('hex')[54:56]+r.encode('hex')[52:54]+r.encode('hex')[50:52]+r.encode('hex')[48:50])
                        if tmp_stc_name == find_application:
				#print r.encode('hex')
				f_mod.write(struct.pack('H',struct.unpack('HH',r[0:4])[0] + 0x14) + struct.pack('H',0))
				#print r[4:24].encode('hex')
				f_mod.write(r[4:16])
				if struct.unpack('HH',r[16:20])[0] > find_allowbackup:
					f_mod.write(struct.pack('<L',struct.unpack('HH',r[16:20])[0] + 0x1))
                                else :
                                        f_mod.write(r[16:20])
				f_mod.write(r[20:24])
				f_mod.write(struct.pack('H',struct.unpack('HH',r[24:28])[0] + 0x1) + struct.pack('H',0))
                                f_mod.write(r[28:32])
                                #print tmp_ac_count
## to add new attribute Chunk ##
                                for i in range(0,tmp_ac_count):
                                        r = f.read(20)
					if struct.unpack('HH',r[4:8])[0] == find_allowbackup:
                                                #print namespaceURI, str_count,0xFFFF,0x80000012,0xFFFFFF
                                                #ns
                                                #print struct.pack('H',struct.unpack('H',namespaceURI)[0]).encode('hex')
                                                #print namespaceURI.encode('hex')
                                                f_mod.write(namespaceURI)
                                                #str_num
                                                f_mod.write(struct.pack('<L',find_allowbackup+1))
                                                #val_str
                                                f_mod.write(struct.pack('HH',0xFFFF,0xFFFF))
                                                #type
                                                f_mod.write(struct.pack('HH',0x0008,0x1200))
                                                #data
                                                f_mod.write(struct.pack('HH',0xFFFF,0xFFFF))

## to change namespace + 1
                                        if r[0:4].encode('hex') != 'ffffffff' and struct.unpack('HH',r[0:4])[0] > find_allowbackup:
                                                f_mod.write(struct.pack('<L',struct.unpack('HH',r[0:4])[0] + 0x1))
						namespaceURI = struct.pack('<L',struct.unpack('HH',r[0:4])[0] + 0x1)
                                        else :
                                                f_mod.write(r[0:4])
						namespaceURI = r[0:4]
## to change attribute name 
                                        if struct.unpack('HH',r[4:8])[0] > find_allowbackup:
                                                f_mod.write(struct.pack('<L',struct.unpack('HH',r[4:8])[0] + 0x1))
                                        else :
                                                f_mod.write(r[4:8])
## to change value and etc...
                                        if r[8:12].encode('hex') == r[16:20].encode('hex'):
                                                if r[8:12].encode('hex') != 'ffffffff' and struct.unpack('HH',r[8:12])[0] > find_allowbackup:
                                                        f_mod.write(struct.pack('<L',struct.unpack('HH',r[8:12])[0] + 0x1))
                                                        f_mod.write(r[12:16])
                                                        f_mod.write(struct.pack('<L',struct.unpack('HH',r[16:20])[0] + 0x1))
                                                else :
                                                        f_mod.write(r[8:20])
                                        else :
                                                if r[8:12].encode('hex') != 'ffffffff' and struct.unpack('HH',r[8:12])[0] > find_allowbackup:
                                                        f_mod.write(struct.pack('<L',struct.unpack('HH',r[8:12])[0] + 0x1))
                                                        f_mod.write(r[12:20])
                                                else :
                                                        f_mod.write(r[8:20])

				continue
			else :
## to change stc name
				f_mod.write(r[0:16])
				if struct.unpack('HH',r[16:20])[0] > find_allowbackup:
					f_mod.write(struct.pack('<L',struct.unpack('HH',r[16:20])[0] + 0x1))
				else :
					f_mod.write(r[16:20])
	                        f_mod.write(r[20:32])
## to change attribute chunk
				for i in range(0,tmp_ac_count):
					r = f.read(20)
## to change namespace + 1
					if r[0:4].encode('hex') != 'ffffffff' and struct.unpack('HH',r[0:4])[0] > find_allowbackup:
						f_mod.write(struct.pack('<L',struct.unpack('HH',r[0:4])[0] + 0x1))
					else :
						f_mod.write(r[0:4])
## to change attribute name 
					if struct.unpack('HH',r[4:8])[0] > find_allowbackup:
						f_mod.write(struct.pack('<L',struct.unpack('HH',r[4:8])[0] + 0x1))
					else : 
						f_mod.write(r[4:8])
## to change value and etc...
					if r[8:12].encode('hex') == r[16:20].encode('hex'):
						#print 'YES',r[8:12].encode('hex'),r[16:20].encode('hex')
						if r[8:12].encode('hex') != 'ffffffff' and struct.unpack('HH',r[8:12])[0] > find_allowbackup:
							f_mod.write(struct.pack('<L',struct.unpack('HH',r[8:12])[0] + 0x1))
							f_mod.write(r[12:16])
							f_mod.write(struct.pack('<L',struct.unpack('HH',r[16:20])[0] + 0x1))
						else :
							f_mod.write(r[8:20])
					else :
						#print 'NO',r[8:12].encode('hex'),r[16:20].encode('hex')
						if r[8:12].encode('hex') != 'ffffffff' and struct.unpack('HH',r[8:12])[0] > find_allowbackup:
							f_mod.write(struct.pack('<L',struct.unpack('HH',r[8:12])[0] + 0x1))
							f_mod.write(r[12:20])
						else :
							f_mod.write(r[8:20])
						
						
        	                continue

## to change end chunk ##
		if tmp == '03011000':
			f_mod.write(r)
			r = f.read(20)
			f_mod.write(r[0:16])
			if r[16:20].encode('hex') != 'ffffffff' and struct.unpack('HH',r[16:20])[0] > find_allowbackup:
				f_mod.write(struct.pack('<L',struct.unpack('HH',r[16:20])[0] + 0x1))
			else :
				f_mod.write(r[16:20])
			continue
		

		if tmp == '01011000':
			f_mod.write(r)
			for i in range(0,5):
                                r = f.read(4)
                                if i == 3:
                                        r = struct.pack('H',struct.unpack('HH',r)[0] + 0x1) + struct.pack('H',0)
                                        #print struct.pack('H',struct.unpack('HH',r)[0] + 0x1).encode('hex')
                                if i == 4:
                                        r = struct.pack('H',struct.unpack('HH',r)[0] + 0x1) + struct.pack('H',0)

                                f_mod.write(r)
			continue

		f_mod.write(r)

	f.close()
	f_mod.close()
	f_tmp.close()


def fchange_for_find(filename):
	f = open(filename,'rb')
	f_mod = open('find.xml','wb')
	str_android = ''

	r = f.read(8)
	tmp = r.encode('hex')

	while tmp != '0b00760065007200':
		r = f.read(1)
		tmp = tmp[2:] + r.encode('hex')
	
	
	for i in range(0,7):
		f_mod.write(tmp[i*2:i*2+2].decode('hex'))

	r = f.read(4)
        tmp = r.encode('hex')
	f_mod.write(r)
	while tmp != '80010800':
		r = f.read(1) 
		f_mod.write(r)
		tmp = tmp[2:] + r.encode('hex')


	f.close()
	f_mod.close()

def finder(filename):
	fchange_for_find(filename)

	f = open('find.xml','rb')
	str_num = ''
	checkNum = 0	
	find_str = dict()
	
	f.read(2)
	while True:
		r = f.read(2)
		
		if not r:
			break
		str_num = str_num+str(r.replace('\x00',''))
		if r == '\00\00':
			find_str.update({str(str_num):checkNum})	
			checkNum = checkNum + 1
			str_num = ''
			f.read(2)
			continue
	return find_str

	f.close()

if __name__ == '__main__':
	os.system('clear')
	while True:
		print 'AndroidManifest modifying tool'
		print '------------------------------'
		print '1. extract AndroidManifest'
		print '2. modify AndroidManifest'
		print '3. zip with modified AndroidManifest'
		print
		print '0. exit'
		print '------------------------------'
		print 'input command : '
		command = raw_input()
		if command == '1':
			os.system('clear')
			print 'input name of file u want to unzip...'
			unzip_filename = raw_input()
			os.system('unzip '+unzip_filename+' -d ./'+unzip_filename.replace('.apk',''))
			os.system('cp ./'+unzip_filename.replace('.apk','')+'/AndroidManifest.xml ./')
			print 'extract completed...'
		elif command == '2':
			os.system('clear')
			filename = 'AndroidManifest.xml'
			find_str = finder(filename)

			if 'debuggable' in find_str.keys():
				fchange_exist(filename)
			else:
				fchange_nonexist(filename)
			print 'modifying completed...'
		elif command == '3':
			os.system('clear')
			print 'input folder name u want to make apk'
			zip_filename = raw_input()
			os.system('mkdir '+zip_filename+'_mod')
			os.system('cp -r ./'+zip_filename+'/* '+zip_filename+'_mod')
			os.system('cp modified.xml '+zip_filename+'_mod')
			os.system('rm AndroidManifest.xml')
			os.system('mv modified.xml AndroidManifest.xml')
			os.system('zip '+zip_filename+'_mod.apk ./'+zip_filename+'/*')
		elif command == '0':
			os.system('clear')
			print 'Bye....'
			sys.exit()
		else:
			print '[!] PLEASE INPUT COMMAND'



	

