'''
    Modulo responsavel por tudo relativo a operacao dos nos
'''

from constantes import *
from udp_util import *
import socket
import sys
from _socket import timeout
from thread import start_new_thread
import time
from math import floor

class No(object):
    '''
        Classe responsavel por todas operacoes dos nos.
    '''

    def inicializa_prox_ant_variaveis(self):
        self.tupla_no_prox_endereco = ("",0)
        self.no_prox_id = -1
        self.tupla_no_ant_endereco = ("",0)
        self.no_ant_id = -1

    def inicializa_sucessor_proximo(self):
        #inicializa no sucessor do prox
        self.no_sucessor_prox_id = -1
        self.tupla_no_sucessor_prox_endereco = ("",0)

    def __init__(self):
        '''
            Metodo responsavel por iniciar as variaveis do No,
            conectar o No no Rendezvous e incluir o No na DHT.
        '''
        self.eh_root = False
        self.no_id = -1
        self.no_root_id = -1
        self.tupla_no_root_endereco = ("",0)

        #informacoes dos nos que estao conectados na dht
        self.inicializa_prox_ant_variaveis()
        
        self.inicializa_sucessor_proximo()

        #referente aos arquivos armazenados no no
        self.arquivos_armazenados = []

        #referente aos finger-tables
        self.finger_tables = [["",-1],["",-1]]

        #cria socket para envio de mensagens
        self.s_envio = self.setup_socket()

        #conversa com o rendesvouz
        self.conecta_rendezvous()

        #inicia thread para escutar as msgs vinda dos nos
        start_new_thread(self.inicia_server, ())

        if not self.eh_root:
            self.entra_dht()
            
        self.atualiza_no_sucessor_proximo()

        #verifica se o proximo No esta vivo
        self.check_running = False
        self.inicia_check_status_proximo_no()

    def inicia_server(self):
        """
            Inicia o servidor responsavel por receber todas as msgs do no.
            possiveis msgs:
            -contato inicial do no nao root para o root
            -contato do no procurando o lugar dele no dht para um no nao root
            -
            -
            -
            -
        """
        s_escuta = cria_socket()
        s_escuta.settimeout(SERVER_TIME_OUT)
        s_escuta = bind_socket(s_escuta, IP_LOCAL, PORTA_BASE_ESCUTA_NOS + self.no_id )

        try :

            while True:
                # receive data from no (data, endereco_porta)
                dados, tupla_endereco_porta = s_escuta.recvfrom(1024)
                print_msg_recebida(dados, tupla_endereco_porta)
                start_new_thread(self.parse_mensagem_recebida, (dados, tupla_endereco_porta,s_escuta))
                #self.parse_mensagem_recebida(dados, tupla_endereco_porta,s_escuta)

        except timeout:
            print "timeout no"

        s_escuta.close()
        return

    def envia_mensagem_no(self, tipo_msg, tupla_endereco, id_destino, mensagem_complemento = ""):
        # IP do root mais a porta que ele escuta, que eh 5000 + numero de id
        mensagem = TIPO + SEPARADOR_ATRIBUTO_VALOR + tipo_msg + SEPARADOR_MSG +\
            ID_NO + SEPARADOR_ATRIBUTO_VALOR + str(self.no_id) + mensagem_complemento

        tupla_endereco_porta = (tupla_endereco[0], PORTA_BASE_ESCUTA_NOS + id_destino)
        nao_enviado = True
        contador = 0
        while nao_enviado:
            try:
                self.s_envio.sendto(mensagem, tupla_endereco_porta)
                print_msg_enviada(mensagem, tupla_endereco_porta)
                d = self.s_envio.recvfrom(1024)
                reply = d[0]
                addr = d[1]
                print_msg_recebida(reply, addr)
        
                parse_reply = reply.split(SEPARADOR_MSG)
                nao_enviado = False
            except timeout:
                contador += 1
                if contador == 3:
                    if tipo_msg == TIPO_CHECK_STATUS_PROXIMO_NO:
                        print "timeout" + str(contador) + " check status no"
                        parse_reply = ["no_fora"]
                        break
                    else:
                        print "nao foi possivel enviar a msg tipo:" + tipo_msg
                        self.fecha_socket()
                        sys.exit()
        
        return parse_reply

    def troca_proximo_no_dht(self, tupla_endereco_porta, s_escuta, mensagem_atributo_valor, id_no_valor):
        #recebe o novo proximo
        novo_id_prox, novo_endereco_proximo = self.parse_mensagem_novo_proximo(mensagem_atributo_valor)
        if novo_id_prox == self.no_id:
            self.inicializa_prox_ant_variaveis()
            self.responde_ACK(s_escuta, tupla_endereco_porta, id_no_valor) 
        else:
            #atualiza o proximo
            self.atualiza_no_proximo(int(novo_id_prox), novo_endereco_proximo) 
            #responde o ack
            self.responde_ACK(s_escuta, tupla_endereco_porta, id_no_valor) 
            #envia uma msg de sou seu novo anterior
            self.envia_mensagem_no(TIPO_SOU_SEU_ANT, self.tupla_no_prox_endereco, self.no_prox_id)

    def parse_mensagem_recebida(self, mensagem, tupla_endereco_porta, s_escuta):
        mensagem_atributo_valor = mensagem.split(SEPARADOR_MSG)

        tipo, tipo_valor = mensagem_atributo_valor[0].split(SEPARADOR_ATRIBUTO_VALOR)
        idNo, id_no_valor = mensagem_atributo_valor[1].split(SEPARADOR_ATRIBUTO_VALOR)

        if tipo_valor == TIPO_CONTATO_INICIAL_ROOT:
            self.contato_inicial_com_root(s_escuta, tupla_endereco_porta, id_no_valor)
            self.atualiza_no_sucessor_proximo()
        elif tipo_valor == TIPO_ACHA_PROX:
            self.responde_acha_proximo(s_escuta, tupla_endereco_porta, id_no_valor)
        elif tipo_valor == TIPO_CHECK_STATUS_PROXIMO_NO:
            self.responde_ACK(s_escuta, tupla_endereco_porta, id_no_valor)
        elif tipo_valor == TIPO_SOU_SEU_PROX:
            self.atualiza_no_proximo(int(id_no_valor), tupla_endereco_porta)
            self.responde_ACK(s_escuta, tupla_endereco_porta, id_no_valor)
            self.atualiza_no_sucessor_proximo()
        elif tipo_valor == TIPO_SOU_SEU_ANT:
            self.atualiza_no_anterior(int(id_no_valor), tupla_endereco_porta)
            self.responde_ACK(s_escuta, tupla_endereco_porta, id_no_valor)
        elif tipo_valor == TIPO_ESTOU_SAINDO_DHT:
            self.troca_proximo_no_dht(tupla_endereco_porta, s_escuta, mensagem_atributo_valor, id_no_valor)
            self.atualiza_no_sucessor_proximo()
        elif tipo_valor == TIPO_CONT_BUSCA:
            end, end_valor = mensagem_atributo_valor[2].split(SEPARADOR_ATRIBUTO_VALOR)
            porta, porta_valor = mensagem_atributo_valor[3].split(SEPARADOR_ATRIBUTO_VALOR)
            id_a, id_arquivo = mensagem_atributo_valor[4].split(SEPARADOR_ATRIBUTO_VALOR)
            id_o, id_origem = mensagem_atributo_valor[5].split(SEPARADOR_ATRIBUTO_VALOR)
            print "Pedido de busca recebido -> Arquivo a buscar: "+id_arquivo+" Responder para No: "+id_origem
            self.continua_busca(int(id_arquivo), [end_valor, int(porta_valor)], int(id_origem))
        elif tipo_valor == TIPO_RESPOSTA_BUSCA:
            id_e, id_encontrado = mensagem_atributo_valor[2].split(SEPARADOR_ATRIBUTO_VALOR)
            conteudo, conteudo_arquivo = mensagem_atributo_valor[3].split(SEPARADOR_ATRIBUTO_VALOR)
            print "Arquivo encontrado no noh de id: "+id_encontrado+" com o seguinte conteudo: "+conteudo_arquivo
            self.resultado_busca(id_encontrado, conteudo_arquivo)

    def responde_acha_proximo(self, s, tupla_endereco_porta, id_no_contatante):
        reply = ID_NO_PROX + SEPARADOR_ATRIBUTO_VALOR + str(self.no_prox_id) + SEPARADOR_MSG +\
                IP_NO_PROX + SEPARADOR_ATRIBUTO_VALOR + self.tupla_no_prox_endereco[0] + SEPARADOR_MSG +\
                PORTA_PROX + SEPARADOR_ATRIBUTO_VALOR + str(self.tupla_no_prox_endereco[1]) + SEPARADOR_MSG

        s.sendto(reply, tupla_endereco_porta)
        print_msg_enviada(reply, tupla_endereco_porta)

    def contato_inicial_com_root(self, s, tupla_endereco_porta, id_no_contatante):
        if self.is_dht_vazia():
            self.entra_primeiro_no_dht(id_no_contatante, tupla_endereco_porta)
            reply = "is_dht_vazia:" + DHT_VAZIA + SEPARADOR_MSG
        else: 
            reply = "is_dht_vazia:" + DHT_NAO_VAZIA + SEPARADOR_MSG +\
                ID_NO_PROX + SEPARADOR_ATRIBUTO_VALOR + str(self.no_prox_id) + SEPARADOR_MSG +\
                IP_NO_PROX + SEPARADOR_ATRIBUTO_VALOR + self.tupla_no_prox_endereco[0] + SEPARADOR_MSG +\
                PORTA_PROX + SEPARADOR_ATRIBUTO_VALOR + str(self.tupla_no_prox_endereco[1]) + SEPARADOR_MSG

        s.sendto(reply, tupla_endereco_porta)
        print_msg_enviada(reply, tupla_endereco_porta)

    def parse_mensagem_novo_proximo(self, mensagem_atributo_valor):
        tipo, novo_id_prox = mensagem_atributo_valor[2].split(SEPARADOR_ATRIBUTO_VALOR)
        ip, ip_no_valor = mensagem_atributo_valor[3].split(SEPARADOR_ATRIBUTO_VALOR)
        porta, porta_no_valor = mensagem_atributo_valor[4].split(SEPARADOR_ATRIBUTO_VALOR)
        
        return int(novo_id_prox), (ip_no_valor,int(porta_no_valor))

    def atualiza_no_anterior(self, id_no, endereco_anterior):
        self.no_ant_id = int(id_no)
        self.tupla_no_ant_endereco = endereco_anterior
        #self.exclui_arquivos(id_no) bugado!
    
    def atualiza_no_proximo(self, id_no, endereco_proximo):
        self.no_prox_id = int(id_no)
        self.tupla_no_prox_endereco = endereco_proximo
    
    def atualiza_no_sucessor_proximo(self):
        if not self.no_prox_id == -1:
            #toda vez que atualiza o proximo atualizar o sucessor do proximo
            #pergunta qual eh o seu proximo para o proximo
            id_no_sucessor, tupla_endereco_sucessor = self.acha_proximo(self.no_prox_id, self.tupla_no_prox_endereco)
            #se o id do proximo for diferente do meu atualizar o sucessor do proximo
            if self.no_id == id_no_sucessor:
                self.no_sucessor_prox_id = -1
                self.tupla_no_sucessor_prox_endereco = ("",0)
            else:
                self.no_sucessor_prox_id = id_no_sucessor
                self.tupla_no_sucessor_prox_endereco = tupla_endereco_sucessor
        
    def exclui_arquivos(self, id_no_prox):
        if self.no_id < id_no_prox:
            for i in range (len(self.arquivos_armazenados) - 1, 0, -1):
                if (self.arquivos_armazenados[i][0] > id_no_prox * 100 - 100):
                    self.arquivos_armazenados.pop(i)
        else:
            for i in range (len(self.arquivos_armazenados) - 1, 0, -1):
                if (self.arquivos_armazenados[i][0] < self.id_no* 100 - 99 and self.arquivos_armazenados[i][0] > id_no_prox*100 - 100):
                    self.arquivos_armazenados.pop(i)



    def entra_primeiro_no_dht(self, id_no_contatante, tupla_endereco_no_contatante):
        self.atualiza_no_proximo(id_no_contatante, tupla_endereco_no_contatante)
        self.atualiza_no_anterior(id_no_contatante, tupla_endereco_no_contatante)
        
        for i in range (1,1000):
            #self.arquivos_armazenados[i] = [i, "Arquivo "+str(i)]
            self.arquivos_armazenados.append([i, "Arquivo "+str(i)])

    def is_dht_vazia(self):
        if self.no_ant_id == -1 and self.no_prox_id -1:
            return True
        return False

    def entra_dht(self): # inserindo um No na rede
        # IP do root mais a porta que ele escuta, que eh 5000 + numero de id
        parse_reply = self.envia_mensagem_no(TIPO_CONTATO_INICIAL_ROOT, self.tupla_no_root_endereco, self.no_root_id)

        status_dht_atributo, status_dht_valor = parse_reply[0].split(SEPARADOR_ATRIBUTO_VALOR)

        if status_dht_valor == DHT_VAZIA:
            self.no_prox_id = self.no_root_id
            self.no_ant_id = self.no_root_id
            self.tupla_no_prox_endereco = self.tupla_no_root_endereco
            self.tupla_no_ant_endereco = self.tupla_no_root_endereco

        elif status_dht_valor == DHT_NAO_VAZIA:
            self.acha_lugar_dht(parse_reply)

    def acha_lugar_dht(self, parse_reply):

        id_no_atual = self.no_root_id
        tupla_endereco_atual = self.tupla_no_root_endereco

        msg_no_variavel_prox = parse_reply[1].split(SEPARADOR_ATRIBUTO_VALOR)
        id_no_prox = int(msg_no_variavel_prox[1])

        msg_no_endereco_prox = parse_reply[2].split(SEPARADOR_ATRIBUTO_VALOR)
        endereco_no_prox = msg_no_endereco_prox[1]

        msg_no_porta_prox = parse_reply[3].split(SEPARADOR_ATRIBUTO_VALOR)
        porta_no_prox = int(msg_no_porta_prox[1])

        tupla_endereco_prox = (endereco_no_prox, porta_no_prox)

        acha_lugar = False

        while not acha_lugar:

            if id_no_atual < id_no_prox:
                if (id_no_atual < self.no_id and self.no_id < id_no_prox) :
                    acha_lugar = True
                    #update proximo e anterior
                    self.atualiza_no_anterior(id_no_atual, tupla_endereco_atual)
                    self.atualiza_no_proximo(id_no_prox, tupla_endereco_prox)
                    self.inclui_arquivos(self.no_id, id_no_prox)

                    #manda msg proximo e anterior
                    self.envia_mensagem_no(TIPO_SOU_SEU_PROX, tupla_endereco_atual, id_no_atual)
                    self.envia_mensagem_no(TIPO_SOU_SEU_ANT, tupla_endereco_prox, id_no_prox)
                else:
                    id_no_atual, tupla_endereco_atual = id_no_prox, tupla_endereco_prox
                    id_no_prox, tupla_endereco_prox = self.acha_proximo(id_no_prox,tupla_endereco_prox)
            else:
                if (id_no_atual > self.no_id and  id_no_prox > self.no_id) or\
                    (id_no_atual < self.no_id and id_no_prox < self.no_id):
                    acha_lugar = True
                    #update proximo e anterior
                    self.atualiza_no_anterior(id_no_atual, tupla_endereco_atual)
                    self.atualiza_no_proximo(id_no_prox, tupla_endereco_prox)
                    self.inclui_arquivos(self.no_id, id_no_prox)

                    #manda msg proximo e anterior
                    self.envia_mensagem_no(TIPO_SOU_SEU_PROX, tupla_endereco_atual, id_no_atual)
                    self.envia_mensagem_no(TIPO_SOU_SEU_ANT, tupla_endereco_prox, id_no_prox)
                else:
                    id_no_atual, tupla_endereco_atual = id_no_prox, tupla_endereco_prox
                    id_no_prox, tupla_endereco_prox = self.acha_proximo(id_no_prox,tupla_endereco_prox)

    def inclui_arquivos(self, id_no, id_no_prox):
        if(id_no < id_no_prox):
            for i in range (self.no_id * 100 - 99, id_no_prox * 100 - 100):
                self.arquivos_armazenados.append([i, "Arquivo "+str(i)])
        else:
            for i in range (self.no_id * 100 - 99, MAX_ARQUIVOS):
                self.arquivos_armazenados.append([i, "Arquivo "+str(i)])
            for i in range (1, id_no_prox*100 - 100):
                self.arquivos_armazenados.append([i, "Arquivo "+str(i)])


    def acha_proximo(self, id_no_prox, tupla_endereco_prox):
        parse_reply = self.envia_mensagem_no(TIPO_ACHA_PROX, tupla_endereco_prox, id_no_prox)

        msg_no_variavel_prox = parse_reply[0].split(SEPARADOR_ATRIBUTO_VALOR)
        id_no = int(msg_no_variavel_prox[1])

        msg_no_endereco_prox = parse_reply[1].split(SEPARADOR_ATRIBUTO_VALOR)
        endereco_no_prox = msg_no_endereco_prox[1]

        msg_no_porta_prox = parse_reply[2].split(SEPARADOR_ATRIBUTO_VALOR)
        porta_no_prox = int(msg_no_porta_prox[1])

        tupla_endereco = (endereco_no_prox, porta_no_prox)

        return id_no, tupla_endereco

    def parse_resposta_rendezvous(self, resposta):
        lista_mensagem = resposta.split(SEPARADOR_MSG)

        atr_id, str_id = lista_mensagem[0].split(SEPARADOR_ATRIBUTO_VALOR)
        self.no_id = int(str_id)

        atr_root, str_root = lista_mensagem[1].split(SEPARADOR_ATRIBUTO_VALOR)
        if str_root == EH_ROOT:
            self.eh_root = True
            for i in range (1,MAX_ARQUIVOS+1):
                self.arquivos_armazenados.append([i, "Arquivo "+str(i)])
        else:
            self.eh_root = False

            atr_id_root, str_id_root = lista_mensagem[2].split(SEPARADOR_ATRIBUTO_VALOR)
            self.no_root_id = int(str_id_root)

            atr_endereco, str_endereco = lista_mensagem[3].split(SEPARADOR_ATRIBUTO_VALOR)
            atr_porta, str_porta = lista_mensagem[4].split(SEPARADOR_ATRIBUTO_VALOR)
            self.tupla_no_root_endereco = (str_endereco,int(str_porta))

    def envia_hello(self, s_envia):
        s_envia.sendto(MENSAGEM_INICIAL, (IP_ACESSAR_RENDEZVOUS, PORTA_RENDEZVOUS))
        print_msg_enviada(MENSAGEM_INICIAL, (IP_ACESSAR_RENDEZVOUS, PORTA_RENDEZVOUS))
        d = s_envia.recvfrom(1024)
        reply = d[0]
        addr = d[1]
        print_msg_recebida(reply, addr)

        if reply is not None:
            self.parse_resposta_rendezvous(reply)

            s_envia.sendto(ACKNOWLEDGE, (IP_ACESSAR_RENDEZVOUS, PORTA_RENDEZVOUS))
            print_msg_enviada(ACKNOWLEDGE, (IP_ACESSAR_RENDEZVOUS, PORTA_RENDEZVOUS))
        else:
            return True

        #se tudo der certo retorna false
        return False

    def conecta_rendezvous(self):

        etapa_hello =  True

        while etapa_hello:
            try :
                etapa_hello = self.envia_hello(self.s_envio)

            except timeout:
                print "timeout na conexao com o rendezvous. Vou tentar de novo!"
                continue

            except socket.error, msg:
                print "Error Code : " + str(msg[0]) + " Message " + msg[1]
                break

        #s.close()

    def setup_socket(self):
        s = cria_socket()
        s.settimeout(CLIENTE_TIME_OUT)
        return s

    def inicia_check_status_proximo_no(self):

        self.check_running = True
        start_new_thread(self.check_status_proximo_no, ())

    def termina_check_status_proximo_no(self):
        self.check_running = False

    def check_status_proximo_no(self):
        while self.check_running:
            time.sleep(INTERVALO_CHECK_STATUS_NO)
            if not self.no_prox_id == -1: 
                parse_reply = self.envia_mensagem_no(TIPO_CHECK_STATUS_PROXIMO_NO, 
                                                    self.tupla_no_prox_endereco, 
                                                    self.no_prox_id)
    
                reply = parse_reply[0]
                if reply == ACKNOWLEDGE:
                    pass
                else:
                    self.reata_dht()
        return
    
    def reata_dht(self):
        if self.no_sucessor_prox_id == -1:
            self.inicializa_prox_ant_variaveis()
            self.inicializa_sucessor_proximo()
        else:
            #envia msg para o sucessor do proximo falando sou seu anterior
            self.envia_mensagem_no(TIPO_SOU_SEU_ANT,
                                   self.tupla_no_sucessor_prox_endereco, 
                                   self.no_sucessor_prox_id)
            #atualiza o proximo
            self.atualiza_no_proximo(self.no_sucessor_prox_id,
                                    self.tupla_no_sucessor_prox_endereco)
            # TODO: avisa rendezvous

    
    def sair_dht(self):
        mensagem_complemento = SEPARADOR_MSG +"novo_id_prox" + SEPARADOR_ATRIBUTO_VALOR + str(self.no_prox_id) + SEPARADOR_MSG +\
            "novo_ip_prox" + SEPARADOR_ATRIBUTO_VALOR + self.tupla_no_prox_endereco[0] + SEPARADOR_MSG +\
            "novo_porta_prox" + SEPARADOR_ATRIBUTO_VALOR + str(self.tupla_no_prox_endereco[1])
        
        #comunicar para os outros nos que eu estou saindo e receber o ack
        parse_reply = self.envia_mensagem_no(TIPO_ESTOU_SAINDO_DHT, 
                                            self.tupla_no_ant_endereco, 
                                            self.no_ant_id, mensagem_complemento)
        
        self.inicializa_prox_ant_variaveis()
        #parar as threads de check status
        #esperar um tempo para que as threads parem
        self.termina_check_status_proximo_no()
        
        #fechar o socket
        self.fecha_socket()
        
        #TODO:avisar rendezvous

    def responde_ACK(self, s, tupla_endereco_porta, id_no_contatante):

        reply = ACKNOWLEDGE + SEPARADOR_MSG

        s.sendto(reply, tupla_endereco_porta)
        print_msg_enviada(reply, tupla_endereco_porta)


    def fecha_socket(self):
        self.s_envio.close()

    def pseudo_hash(self, nome_arquivo):
        id_arquivo = nome_arquivo.split(' ')
        return (int(id_arquivo[1]))

    def calcula_id_no_arquivo(self, id_arquivo):
        posicao = int(floor((id_arquivo - 1)/(MAX_ARQUIVOS/(MAX_SEQUENCIAL+1))))
        print posicao

        if SEQUENCIAL == True:
            return posicao
        else:
            return 2**posicao

    def inicia_busca(self):


        nome_arquivo = raw_input("Digite o nome do arquivo: ")
        id_arquivo = self.pseudo_hash(nome_arquivo)
        id_no_responsavel = self.calcula_id_no_arquivo(id_arquivo)

        print  "Numero de arquivos armazenados localmente: " + str(len(self.arquivos_armazenados))
        tupla_endereco_no_origem = [IP_LOCAL, PORTA_BASE_ESCUTA_NOS + self.no_id]
        print "Meu Id: " + str(self.no_id) +" - Id Responsavel: " + str(id_no_responsavel) +" - Proximo Id: " + str(self.no_prox_id)
        if self.no_id == id_no_responsavel:
            print "Este noh (ID"+ str(self.no_id) + ") eh o responsavel pelo arquivo"
            for i in range(0,len(self.arquivos_armazenados)-1):
                if self.arquivos_armazenados[i][0] == id_arquivo:
                    print("Sucesso, arquivo encontrado no id "+str(self.no_id))
                    return
            print "Porem o arquivo nao se encontra armazenado na tabela"
            return
        elif self.no_id > id_no_responsavel:
            if self.no_id > self.no_prox_id:
                if self.no_prox_id > id_no_responsavel:
                    print "Este noh (ID"+ str(self.no_id) +") eh o responsavel pelo arquivo"
                    for i in range(0,len(self.arquivos_armazenados)-1):
                        if self.arquivos_armazenados[i][0] == id_arquivo:
                            print("Sucesso, arquivo encontrado no id "+str(self.no_id))
                            return
                    print "Porem o arquivo nao se encontra armazenado na tabela"
                    return
                else:
                    print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, self.no_id)
            else:
                print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, int(self.no_prox_id), id_arquivo, tupla_endereco_no_origem, self.no_id)
        else:
            #if self.finger_tables[1][1] <= id_no_responsavel:
            #    if self.finger_tables[1][1] < self.no_id:
            #        pass
            #    else:
            #        self.envia_continua_busca(TIPO_CONT_BUSCA, self.finger_tables[1][0], self.finger_tables[1][1], id_arquivo, tupla_endereco_no_origem, self.no_id)
            #        return
            #if self.finger_tables[0][1] <= id_no_responsavel:

            #    if self.finger_tables[0][1] < self.no_id:
            #        pass
            #    else:
            #        self.envia_continua_busca(TIPO_CONT_BUSCA, self.finger_tables[0][0], self.finger_tables[0][1], id_arquivo, tupla_endereco_no_origem, self.no_id)
            #        return
            if self.no_prox_id <= id_no_responsavel:
                if self.no_prox_id == id_no_responsavel:
                    print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, self.no_id)
                    return                
                else:
                    if self.no_prox_id < self.no_id:
                        print("Sucesso, arquivo encontrado no id "+str(self.no_id))
                        return
                    else:
                        print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                        self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, self.no_id)
                        return                        
            else:
                print("Sucesso, arquivo encontrado no id "+str(self.no_id))
                return
                #if self.no_prox_id != self.no_id:
                #    
                #else:
                #    print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                #    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, self.no_id)
                #    return    

    def continua_busca(self, id_arquivo, tupla_endereco_no_origem, id_origem):
        id_no_responsavel = self.calcula_id_no_arquivo(id_arquivo)
        print  "Numero de arquivos armazenados localmente: " + str(len(self.arquivos_armazenados))
        if self.no_id == id_no_responsavel:
            self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, "Arquivo "+str(id_arquivo))
            return
            #for i in range(0,len(self.arquivos_armazenados)-1):
            #    if self.arquivos_armazenados[i][0] == id_arquivo:
            #        self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, self.arquivos_armazenados[i][1])
        elif self.no_id > id_no_responsavel:
            if self.no_id > self.no_prox_id:
                if self.no_prox_id > id_no_responsavel:
                    print "Arquivo encontrado"
                    print "Enviando resposta de busca para o no " + str(id_origem)
                    self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, "Arquivo "+str(id_arquivo))
                    return
                    #for i in range(0,len(self.arquivos_armazenados)-1):
                    #    if self.arquivos_armazenados[i][0] == id_arquivo:
                    #        self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, self.arquivos_armazenados[i][1])
                else:
                    print "Continua busca no No: " + str(self.no_prox_id)
                    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, id_origem)
            else:
                self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, id_origem)
        else:
            #if self.finger_tables[1][1] <= id_no_responsavel:

            #    if self.finger_tables[1][1] < self.no_id:
            #        pass
            #    else:
            #        self.envia_continua_busca(TIPO_CONT_BUSCA, self.finger_tables[1][0], self.finger_tables[1][1], id_arquivo, tupla_endereco_no_origem, id_origem)
            #        return
            #if self.finger_tables[0][1] <= id_no_responsavel:

            #    if self.finger_tables[0][1] < self.no_id:
            #        pass
            #    else:
            #        self.envia_continua_busca(TIPO_CONT_BUSCA, self.finger_tables[0][0], self.finger_tables[0][1], id_arquivo, tupla_endereco_no_origem, id_origem)
            #        return
            if self.no_prox_id <= id_no_responsavel:
                if self.no_prox_id == id_no_responsavel:
                    print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, id_origem)
                    return                
                else:
                    if self.no_prox_id < self.no_id:
                        print "Arquivo encontrado"
                        print "Enviando resposta de busca para o no " + str(id_origem)
                        self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, "Arquivo "+str(id_arquivo))
                        return
                    else:
                        print "Enviar pedido de busca para o no " + str(self.no_prox_id)
                        self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_no_prox_endereco, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, id_origem)
                        return    
            else:
                print "Arquivo encontrado"
                print "Enviando resposta de busca para o no " + str(id_origem)
                self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, "Arquivo "+str(id_arquivo))
                return
                    
                #if self.no_prox_id < self.no_id:
                    #for i in range(0,len(self.arquivos_armazenados)-1):
                    #    if self.arquivos_armazenados[i][0] == id_arquivo:
                    #        self.envia_resposta_busca(TIPO_RESPOSTA_BUSCA, tupla_endereco_no_origem, id_origem, self.no_id, self.arquivos_armazenados[i][1])
                    #       retu
                #else:
                #    print "Continua busca no No: " + str(self.no_prox_id)
                #    self.envia_continua_busca(TIPO_CONT_BUSCA, self.tupla_endereco_prox, self.no_prox_id, id_arquivo, tupla_endereco_no_origem, id_origem)
                #    return

    def envia_continua_busca(self, tipo_msg, tupla_endereco, id_destino, id_arquivo, tupla_endereco_origem, id_origem):

        mensagem = TIPO + SEPARADOR_ATRIBUTO_VALOR + tipo_msg + SEPARADOR_MSG +\
                ID_NO + SEPARADOR_ATRIBUTO_VALOR + str(self.no_id)+ SEPARADOR_MSG +\
                 "Endereco" + SEPARADOR_ATRIBUTO_VALOR + tupla_endereco_origem[0]+ SEPARADOR_MSG +\
                 "Porta"+ SEPARADOR_ATRIBUTO_VALOR + str(tupla_endereco_origem[1])+ SEPARADOR_MSG +\
                 "Id_arquivo" + SEPARADOR_ATRIBUTO_VALOR + str(id_arquivo) + SEPARADOR_MSG +\
                 "Id_origem"+ SEPARADOR_ATRIBUTO_VALOR + str(id_origem)

        tupla_endereco_porta = (tupla_endereco[0], PORTA_BASE_ESCUTA_NOS + id_destino)

        self.s_envio.sendto(mensagem, tupla_endereco_porta)

    def envia_resposta_busca(self, tipo_msg, tupla_endereco, id_destino, id_encontrado, conteudo_arquivo):
        mensagem = TIPO + SEPARADOR_ATRIBUTO_VALOR + tipo_msg + SEPARADOR_MSG +\
                ID_NO + SEPARADOR_ATRIBUTO_VALOR + str(self.no_id)+ SEPARADOR_MSG +\
                 "Id_Encontrado" + SEPARADOR_ATRIBUTO_VALOR + str(id_encontrado) + SEPARADOR_MSG +\
                 "Conteudo_arquivo"+ SEPARADOR_ATRIBUTO_VALOR + conteudo_arquivo + SEPARADOR_MSG

        tupla_endereco_porta = (tupla_endereco[0], PORTA_BASE_ESCUTA_NOS + id_destino)

        self.s_envio.sendto(mensagem, tupla_endereco_porta)

    def resultado_busca(self, id_encontrado, conteudo_arquivo):
        print "Arquivo encontrado no noh de id: "+id_encontrado+" com o seguinte conteudo: "+conteudo_arquivo
