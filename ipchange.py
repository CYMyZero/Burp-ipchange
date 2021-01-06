from javax.swing import JPanel, JTextField, JButton, JLabel, BoxLayout, JRadioButton, ButtonGroup, BorderFactory
from burp import IBurpExtender, IExtensionStateListener, ITab, IHttpListener
#from java.awt import GridLayout
#from java.io import File
#from java.lang import System
import boto3
#import re
import time,sys,os.path,random

EXT_NAME = 'ipchange'


class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IHttpListener):
    def __init__(self):
        self.allEndpoints = []
        self.currentEndpoint = 0
        self.aws_access_key_id = ''
        self.aws_secret_accesskey = ''
        self.enabled_regions = {}

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.helpers
        self.isEnabled = False

        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.setExtensionName(EXT_NAME)
        callbacks.addSuiteTab(self)


    def list_proxy(self,event,a):
        
        filename = self.proxylist.text
        self.listdl=[]
        if not os.path.isfile(filename):
            return
        with open(filename,'r') as f:
            for line in f:
                lines=line.strip()
                if lines!="":
                    host=list(lines.strip('\n').split(','))
                    host.append(1)
                    self.listdl.append(host)
        self.num=0
        print(self.listdl)
    # Called on "Enable" button click to spin up the API Gateway

    def enableGateway(self, event):
        self.list_proxy(self,event)
        self.isEnabled = True
        self.enable_button.setEnabled(False)
        self.failremove.setEnabled(False)
        self.sleep.setEnabled(False)
        self.proxylist.setEnabled(False)
        self.target_host.setEnabled(False)
        self.disable_button.setEnabled(True)
        return

    # Called on "Disable" button click to delete API Gateway
    def disableGateway(self, event):
        self.isEnabled = False
        self.enable_button.setEnabled(True)
        self.failremove.setEnabled(True)
        self.sleep.setEnabled(True)
        self.proxylist.setEnabled(True)
        self.target_host.setEnabled(True)
        self.disable_button.setEnabled(False)
        return

    def getCurrEndpoint():

        return

    # Traffic redirecting
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        #

        if messageIsRequest and self.isEnabled:

            httpService = messageInfo.getHttpService()
            #
            for i in range(0,len(self.listdl)-1):
                if self.listdl[i][1]>self.failremove.text:
                    del self.listdl[i]
            #
            if(len(self.listdl)<1):
                host=[]
                host.append(self.target_host.text)
                host.append(1)
                self.listdl.append(host)
            if self.https_button.isSelected() == True:
                ssl= True
            else:
                ssl= False
            num=random.randint(0,len(self.listdl)-1)
            self.num=num
            self.httpstr=self.listdl[num][0]
            self.listdl[num][1]+=1
            messageInfo.setHttpService(
                self.helpers.buildHttpService(
                                self.httpstr.split(':')[0],
                                int(self.httpstr.split(
                                    ':')[1]), ssl
                            )
                )

            requestInfo = self.helpers.analyzeRequest(messageInfo)
            new_headers = requestInfo.headers
            #
            req_head = new_headers[0]

            if 'http://' in req_head or 'https://' in req_head:
                new_headers[0] = req_head
            else:
                new_headers[0] = req_head.replace(
                    ' ', ' '+str(httpService), 1)
            body = messageInfo.request[requestInfo.getBodyOffset():len(
                messageInfo.request)]
                
            messageInfo.request = self.helpers.buildHttpMessage(
                new_headers,
                body)
            
            time.sleep(float(self.sleep.text))

            print(self.listdl)
        else:
            if self.isEnabled:
                self.listdl[self.num][1]-=1
    # Tab name
    def getTabCaption(self):
        return EXT_NAME

    # Layout the UI
    def getUiComponent(self):

        self.panel = JPanel()

        self.main = JPanel()
        self.main.setLayout(BoxLayout(self.main, BoxLayout.Y_AXIS))

        self.proxy_list = JPanel()
        self.main.add(self.proxy_list)
        self.proxy_list.setLayout(
            BoxLayout(self.proxy_list, BoxLayout.X_AXIS))
        self.proxy_list.add(JLabel('file_path(proxy_list): '))
        self.proxylist = JTextField("C:\Users\Administrator\Desktop\ip.txt", 25)

        self.proxy_list.add(self.proxylist)

        self.sleep_panel = JPanel()
        self.main.add(self.sleep_panel)
        self.sleep_panel.setLayout(
            BoxLayout(self.sleep_panel, BoxLayout.X_AXIS))
        self.sleep_panel.add(JLabel('Sleep(s): '))
        self.sleep = JTextField('0', 25)
        self.sleep_panel.add(self.sleep)


        self.failremove_panel = JPanel()
        self.main.add(self.failremove_panel)
        self.failremove_panel.setLayout(
            BoxLayout(self.failremove_panel, BoxLayout.X_AXIS))
        self.failremove_panel.add(JLabel('fail remove(freq): '))
        self.failremove = JTextField('5', 25)
        self.failremove_panel.add(self.failremove)


        self.target_host_panel = JPanel()
        self.main.add(self.target_host_panel)
        self.target_host_panel.setLayout(
            BoxLayout(self.target_host_panel, BoxLayout.X_AXIS))
        self.target_host_panel.add(JLabel('Target host: '))
        self.target_host = JTextField('127.0.0.1:8080', 25)
        self.target_host_panel.add(self.target_host)

        self.buttons_panel = JPanel()
        self.main.add(self.buttons_panel)
        self.buttons_panel.setLayout(
            BoxLayout(self.buttons_panel, BoxLayout.X_AXIS))
        self.enable_button = JButton('Enable', actionPerformed= self.enableGateway)
        self.buttons_panel.add(self.enable_button)
        self.disable_button = JButton('Disable', actionPerformed= self.disableGateway)
        self.buttons_panel.add(self.disable_button)
        self.disable_button.setEnabled(False)

        self.protocol_panel = JPanel()
        self.main.add(self.protocol_panel)
        self.protocol_panel.setLayout(
            BoxLayout(self.protocol_panel, BoxLayout.Y_AXIS))
        self.protocol_panel.add(JLabel("Target Protocol:"))
        self.https_button = JRadioButton("HTTPS", False)
        self.http_button = JRadioButton("HTTP", True)
        self.protocol_panel.add(self.http_button)
        self.protocol_panel.add(self.https_button)
        buttongroup = ButtonGroup()
        buttongroup.add(self.https_button)
        buttongroup.add(self.http_button)


        self.panel.add(self.main)
        return self.panel
