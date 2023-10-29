import os
import sys
import json
import random
import asyncio
import socket
import websockets
import argparse
import logging

from common.crypt import AesEcbCipher as Cipher

logger = logging.getLogger(__name__)

TUNNEL_STATE_ESTABLISHED    = 0
TUNNEL_STATE_NO_SERVER      = 1
TUNNEL_STATE_NO_RESPONSE    = 2
TUNNEL_STATE_WRONG_PASSWORD = 3
TUNNEL_STATE_WRONG_CONNECT  = 4

class WebsocketBridge(object):
    def __init__(self, cfg, reader, writer):
        self.cfg = cfg
        self.local_reader = reader
        self.local_writer = writer
        self.websocket = None
        self.selected_tunnel_server = None
        self.cipher = None
        self.remote_host = ''
        self.remote_port = -1

    def select_tunnel_server(self):
        if self.cfg['server']['balance'] == 'off':
            if self.cfg['server']['default'] in self.cfg['server']['all'].keys():
                return self.cfg['server']['all'][self.cfg['server']['default']]
            logger.error(f"select_tunnel_server: not found server name={self.cfg['server']['default']}")
            return None
        elif self.cfg['balance'] == 'on':
            if self.cfg['server']['all']:
                return random.choice(self.cfg['server']['all'])
            logger.error(f'select_tunnel_server: not found server balance=on')
            return None
        return None

    async def open_tunnel(self, host, port):
        tunnel_server = self.select_tunnel_server()
        if not tunnel_server:
            return TUNNEL_STATE_NO_SERVER
        self.selected_tunnel_server = tunnel_server
        self.cipher = Cipher(tunnel_server['password'])
        url = 'ws://%s:%d/'%(tunnel_server['ip'], tunnel_server['port'])
        try:
            self.websocket = await websockets.connect(url)
        except Exception as e:
            logger.warning(f'failed to open remote tunnel: {e}')
            return TUNNEL_STATE_NO_RESPONSE

        if host=='127.0.0.1' or host=='localhost':
            logger.warning('Should not access localhost via tunnel!')

        self.remote_host = host
        self.remote_port = port
        msg = '{ "host": "%s", "port": %d }' % (host, port)
        # print(f"open tunnel: {msg} ...")
        await self.websocket.send(self.cipher.encrypt(msg.encode()))
        data = await self.websocket.recv()
        data = self.cipher.decrypt(data)
        if data == b'\x01':
            logger.warning(f'tunnel negotiation: server failed to decrypt data:{data} remote:"{host}:{port}"')
            return TUNNEL_STATE_WRONG_PASSWORD
        if data == b'\x02':
            logger.warning(f'tunnel negotiation: server failed to connect remote:"{host}:{port}"')
            return TUNNEL_STATE_WRONG_CONNECT
        
        # print(f"open tunnel: {msg} success!")
        return TUNNEL_STATE_ESTABLISHED

    async def send_data(self, data: bytes):
        await self.websocket.send(self.cipher.encrypt(data))

    async def flow_up(self):
        try:
            await self._flow_up()
        except Exception as e:
            pass
        
    async def flow_down(self):
        try:
            await self._flow_down()
        except Exception as e:
            pass

    async def _flow_up(self):
        logger.debug(f'{self.remote_host}:{self.remote_port} flow-up ( socks -> [client] -> server ) starting ...')
        while True:
            #print(f'flow_up waiting read ...')
            data = await self.local_reader.read(4096)
            #print(f'request:\n{len(data)}')
            if not data:
                break
            await self.websocket.send(self.cipher.encrypt(data))
        await self.websocket.close()
        logger.debug(f'{self.remote_host}:{self.remote_port} flow-up ( socks -> [client] -> server ) stoping ...')

    async def _flow_down(self):
        logger.debug(f'{self.remote_host}:{self.remote_port} flow-down ( socks <- [client] <- server ) starting ...')
        async for data in self.websocket:
            self.local_writer.write(self.cipher.decrypt(data))
            await self.local_writer.drain()
        self.local_writer.close()
        await self.local_writer.wait_closed()
        logger.debug(f'{self.remote_host}:{self.remote_port} flow-down ( socks <- [client] <- server ) stoping ...')

    async def transfer(self):
        #await asyncio.wait([self.flow_up(), self.flow_down()], return_when=asyncio.tasks.FIRST_COMPLETED)
        await asyncio.wait([self.flow_up(), self.flow_down()])
