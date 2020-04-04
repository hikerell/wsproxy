import os
import sys
import json
import asyncio
import websockets
import logging
import argparse

from common.crypt import AesEcbCipher as Cipher

logger = logging.getLogger(__name__)

class ServerTcpRelay(object):
    STAGE_INITIALIZED = 0
    STAGE_AUTHENRIZED = 1
    STAGE_FLOWING     = 2
    def __init__(self, cfg, loop, websocket):
        self.cfg = cfg
        self.loop = loop
        self.websocket = websocket
        self.cipher = Cipher(self.cfg['server']['password'])
        self.remote_reader = None
        self.remote_writer = None

    async def flow_up(self):
        logger.debug('flow-up ( client -> [server] -> remote ) starting ...')
        async for data in self.websocket:
            self.remote_writer.write(self.cipher.decrypt(data))
            await self.remote_writer.drain()
        self.remote_writer.close()
        await self.remote_writer.wait_closed()
        logger.debug('flow-up ( client -> [server] -> remote ) stopping ...')

    async def flow_down(self):
        logger.debug('flow-down ( client <- [server] <- remote ) starting ...')
        while True:
            data = await self.remote_reader.read(4096)
            if not data:
                break
            await self.websocket.send(self.cipher.encrypt(data))
        await self.websocket.close()
        logger.debug('flow-down ( client <-[server] <- remote ) stopping ...')

    async def start(self):
        #await asyncio.wait([self.flow_up(), self.flow_down()], return_when=asyncio.tasks.FIRST_COMPLETED)
        await asyncio.wait([self.flow_up(), self.flow_down()])

    async def negotiate(self):
        data = await self.websocket.recv()
        try:
            logger.debug(f'negotiate: {data.hex()}')
            data = self.cipher.decrypt(data)
            logger.debug(f'negotiate decrypt: {data.hex()}')
            text = data.decode()
            logger.debug(f'negotiate: {text}')
        except Exception as e:
            logger.debug(f'parse_negotiation_packet: {e}')
            await self.websocket.send(self.cipher.encrypt(b'\x01'))
            await self.websocket.close()
            return False

        try:
            msg = json.loads(text)
            self.remote_reader, self.remote_writer = await asyncio.open_connection(msg['host'], msg['port'])
        except Exception as e:
            logger.debug(f'parse_negotiation_packet: {e}')
            await self.websocket.send(self.cipher.encrypt(b'\x02'))
            await self.websocket.close()
            return False
        await self.websocket.send(self.cipher.encrypt(b'\x00'))
        return True

async def ws_handler(cfg, websocket, path):
    try:
        logger.debug('client entering ...')
        loop = asyncio.get_running_loop()
        relay = ServerTcpRelay(cfg, loop, websocket)
        succ = await relay.negotiate()
        if not succ:
            return
        await relay.start()
        logger.debug('client exiting ...')
    except Exception as e:
        logger.exception(e)

def start(cfg):
    host, port = cfg['server']['host'], cfg['server']['port']
    logger.info(f'websocket server listening on {host}:{port}')
    start_server = websockets.serve(lambda s, p: ws_handler(cfg, s, p), host, port)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
