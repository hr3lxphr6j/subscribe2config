#!/usr/bin/env python3
import base64
import json
import logging
import os
from argparse import ArgumentParser, Namespace
from collections import UserDict
from dataclasses import dataclass, field
from typing import Any, AnyStr, Dict, List, Optional, Union
from urllib.parse import ParseResult, parse_qs, unquote, urlparse
from functools import partial

import requests
from dataclasses_json import config, dataclass_json

logging.basicConfig(
    level=logging.DEBUG if os.getenv('DEBUG') else logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S',
    format='[%(asctime)s][%(levelname)s]: %(message)s',
)


class ConvertError(RuntimeError):
    pass


class Queries(UserDict[AnyStr, List[AnyStr]]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._accessed_fields = set()

    def get(self, __key):
        if self.__contains__(__key):
            self._accessed_fields.add(__key)
        return super().get(__key)

    def __getitem__(self, __key):
        if self.__contains__(__key):
            self._accessed_fields.add(__key)
        return super().__getitem__(__key)

    def get_value(self, key: AnyStr, default=None) -> Optional[AnyStr]:
        values = self.get(key)
        if not values or not values[0]:
            return default
        return values[0]


@dataclass_json
@dataclass
class StreamSettings:

    network: AnyStr = 'tcp'
    security: AnyStr = 'none'

    @dataclass_json
    @dataclass
    class TLSObject:
        serverName: Optional[AnyStr] = None
        alpn: Optional[List[AnyStr]] = None
        allowInsecure: Optional[bool] = False

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.TLSObject':
            obj = StreamSettings.TLSObject()

            server_name = queries.get_value('sni')
            if server_name:
                obj.serverName = server_name

            allow_insecure = queries.get_value('allowInsecure')
            obj.allowInsecure = allow_insecure == '1'

            alpn = queries.get_value('alpn')
            if alpn:
                obj.alpn = alpn.split(',')

            return obj

    tlsSettings: Optional[TLSObject] = None

    @dataclass_json
    @dataclass
    class TcpObject:
        type_: AnyStr = field(metadata=config(field_name='type'), default='none')

        @dataclass_json
        @dataclass
        class HTTPRequestObject:
            version: Optional[AnyStr] = '1.1'
            method: Optional[AnyStr] = 'GET'
            path: Optional[List[AnyStr]] = field(default_factory=lambda: ['/'])
            headers: Optional[Dict[AnyStr, List[AnyStr]]] = None

            @staticmethod
            def from_queries(queries: Queries) -> 'StreamSettings.TcpObject.HTTPRequestObject':
                obj = StreamSettings.TcpObject.HTTPRequestObject()

                path = queries.get_value('path')
                if path:
                    obj.path = path

                host = queries.get_value('host')
                if host:
                    obj.headers = {'Host': [host]}

                return obj

        request: Optional[HTTPRequestObject] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.TcpObject':
            obj = StreamSettings.TcpObject()
            header_type = queries.get_value('headerType')
            if header_type:
                if header_type not in ('none', 'http'):
                    raise ConvertError('unexpected tcp header type: {}'.format(header_type))

                obj.type_ = header_type

            if obj.type_ == 'http':
                obj.request = StreamSettings.TcpObject.HTTPRequestObject.from_queries(queries)

            return obj

    tcpSettings: Optional[TcpObject] = None

    @dataclass_json
    @dataclass
    class KcpObject:
        @dataclass_json
        @dataclass
        class HeaderObject:
            type_: AnyStr = field(metadata=config(field_name='type'), default='none')

        mtu: Optional[int] = 1350
        tti: Optional[int] = 50
        uplinkCapacity: Optional[int] = 5
        downlinkCapacity: Optional[int] = 20
        congestion: Optional[bool] = False
        readBufferSize: Optional[int] = 2
        writeBufferSize: Optional[int] = 2
        header: Optional[HeaderObject] = None
        seed: Optional[AnyStr] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.KcpObject':
            obj = StreamSettings.KcpObject()

            header_type = queries.get_value('headerType')
            if header_type:
                if header_type not in ('none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard'):
                    raise ConvertError('unexpected kcp header type: {}'.format(header_type))
                obj.header = StreamSettings.KcpObject.HeaderObject(type_=header_type)

            seed = queries.get_value('seed')
            if seed:
                obj.seed = seed

            return obj

    kcpSettings: Optional[KcpObject] = None

    @dataclass_json
    @dataclass
    class WebSocketObject:
        path: Optional[AnyStr] = '/'
        headers: Optional[Dict[AnyStr, AnyStr]] = None
        maxEarlyData: Optional[int] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.WebSocketObject':
            obj = StreamSettings.WebSocketObject()

            path = queries.get_value('path')
            if path:
                obj.path = path

            host = queries.get_value('host')
            if host:
                obj.headers = {'Host': host}

            return obj

    wsSettings: Optional[WebSocketObject] = None

    @dataclass_json
    @dataclass
    class HttpObject:
        host: Optional[List[AnyStr]] = None
        path: Optional[AnyStr] = '/'
        method: Optional[AnyStr] = 'PUT'
        headers: Optional[Dict[AnyStr, List[AnyStr]]] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.HttpObject':
            obj = StreamSettings.HttpObject()

            path = queries.get_value('path')
            if path:
                obj.path = path

            host = queries.get_value('host')
            if host:
                obj.host = [host]

            return obj

    httpSettings: Optional[HttpObject] = None

    @dataclass_json
    @dataclass
    class QUICObject:
        @dataclass_json
        @dataclass
        class HeaderObject:
            type_: AnyStr = field(metadata=config(field_name='type'), default='none')

        security: Optional[AnyStr] = 'none'
        key: Optional[AnyStr] = None
        header: Optional[HeaderObject] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.QUICObject':
            obj = StreamSettings.QUICObject()

            quic_security = queries.get_value('quicSecurity')
            if quic_security:
                if quic_security not in ('none', 'aes-128-gcm', 'chacha20-poly1305'):
                    raise ConvertError('unexpected quic security: {}'.format(quic_security))
                obj.security = quic_security

            key = queries.get_value('key')
            if key:
                obj.key = key

            header_type = queries.get_value('headerType')
            if header_type:
                if header_type not in ('none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard'):
                    raise ConvertError('unexpected quic header type: {}'.format(header_type))
                obj.header = StreamSettings.QUICObject.HeaderObject(type_=header_type)

            return obj

    quicSettings: Optional[QUICObject] = None

    @dataclass_json
    @dataclass
    class GrpcObject:
        serviceName: Optional[AnyStr] = None
        multiMode: Optional[bool] = None

        @staticmethod
        def from_queries(queries: Queries) -> 'StreamSettings.GrpcObject':
            obj = StreamSettings.GrpcObject()

            service_name = queries.get_value('serviceName')
            if service_name:
                obj.serviceName = service_name

            mode = queries.get_value('mode')
            if mode == 'multi':
                obj.multiMode = True

            return obj

    grpcSettings: Optional[GrpcObject] = None

    @dataclass_json
    @dataclass
    class SockoptObject:
        mark: Optional[int] = 0
        tcpFastOpen: Optional[bool] = False
        tcpFastOpenQueueLength: Optional[int] = 4096
        tproxy: Optional[str] = 'off'
        tcpKeepAliveInterval: Optional[int] = 0

    sockopt: Optional[SockoptObject] = None

    @staticmethod
    def from_queries(queries: Queries) -> 'StreamSettings':
        settings = StreamSettings()

        # 传输协议
        _type = queries.get_value('type')
        if _type:
            if _type not in ('tcp', 'kcp', 'ws', 'h2', 'http', 'quic', 'grpc'):
                raise ConvertError('unexpected type: {}'.format(_type))
            settings.network = _type

        # tcp 配置
        if settings.network == 'tcp':
            settings.tcpSettings = StreamSettings.TcpObject.from_queries(queries)
        # kcp 配置
        elif settings.network == 'kcp':
            settings.kcpSettings = StreamSettings.KcpObject.from_queries(queries)
        # websocket 配置
        elif settings.network == 'ws':
            settings.wsSettings = StreamSettings.WebSocketObject.from_queries(queries)
        # http/2 配置
        elif settings.network in ('h2', 'http'):
            settings.httpSettings = StreamSettings.HttpObject.from_queries(queries)
        # quic 配置
        elif settings.network == 'quic':
            settings.quicSettings = StreamSettings.QUICObject.from_queries(queries)
        # grpc 配置
        elif settings.network == 'grpc':
            settings.grpcSettings = StreamSettings.GrpcObject.from_queries(queries)

        # tls 配置
        security = queries.get_value('security')
        if security:
            settings.security = security
        if settings.security == 'tls':
            settings.tlsSettings = StreamSettings.TLSObject.from_queries(queries)

        return settings

    @staticmethod
    def from_v2_dict(v2_dict: Dict[AnyStr, AnyStr]) -> 'StreamSettings':
        settings = StreamSettings()
        if v2_dict.get('tls') == 'tls':
            settings.security = 'tls'
            settings.tlsSettings = StreamSettings.TLSObject(
                serverName=v2_dict.get('sni'),
                alpn=v2_dict.get('alpn').split(',') if v2_dict.get('alpn') else None
            )

        net = v2_dict.get('net')
        if net == 'tcp':
            settings.network = 'tcp'
            settings.tcpSettings = StreamSettings.TcpObject(
                type_=v2_dict.get('type'),
                request=StreamSettings.TcpObject.HTTPRequestObject(
                    path=v2_dict.get('path'),
                    headers={'Host': [v2_dict.get('host')]} if v2_dict.get('host') else None
                ) if v2_dict.get('type') == 'http' else None
            )
        elif net == 'kcp':
            settings.network = 'kcp'
            settings.kcpSettings = StreamSettings.KcpObject(
                header=StreamSettings.KcpObject.HeaderObject(
                    type_=v2_dict.get('type')
                ) if v2_dict.get('type') else None,
                seed=v2_dict.get('path')
            )
        elif net == 'ws':
            settings.network = 'ws'
            settings.wsSettings = StreamSettings.WebSocketObject(
                path=v2_dict.get('path'),
                headers={'Host': v2_dict.get('host')} if v2_dict.get('host') else None,
            )
        elif net in ('h2', 'http'):
            settings.network = 'h2'
            settings.wsSettings = StreamSettings.HttpObject(
                path=v2_dict.get('path'),
                host=[v2_dict.get('host')] if v2_dict.get('host') else None,
            )
        elif net == 'quic':
            settings.network = 'quic'
            settings.quicSettings = StreamSettings.QUICObject(
                key=v2_dict.get('path'),
                security=v2_dict.get('host'),
                header=StreamSettings.QUICObject.HeaderObject(
                    type_=v2_dict.get('type')) if v2_dict.get('type') else None
            )
        elif net == 'grpc':
            settings.network = 'grpc'
            settings.grpcSettings = StreamSettings.GrpcObject(
                serviceName=v2_dict.get('path'),
                multiMode=v2_dict.get('type') == 'multi'
            )
        return settings


@dataclass_json
@dataclass
class VlessOCO:
    @dataclass_json
    @dataclass
    class ServerObject:
        address: str
        port: int

        @dataclass_json
        @dataclass
        class UserObject:
            id: str
            encryption: Optional[str] = 'none'
            level: Optional[int] = None

            @staticmethod
            def from_url(url: ParseResult, queries: Queries) -> 'VlessOCO.ServerObject.UserObject':
                return VlessOCO.ServerObject.UserObject(
                    id=url.username,
                    encryption=queries.get_value('encryption', 'none')
                )

        users: Optional[List[UserObject]] = None

        @staticmethod
        def from_url(url: ParseResult, queries: Queries) -> 'VlessOCO.ServerObject':
            return VlessOCO.ServerObject(
                address=url.hostname,
                port=url.port,
                users=[VlessOCO.ServerObject.UserObject.from_url(url, queries)]
            )

    vnext: Optional[List[ServerObject]] = None

    @staticmethod
    def from_url(url: ParseResult, queries: Queries) -> 'VlessOCO':
        return VlessOCO(vnext=[VlessOCO.ServerObject.from_url(url, queries)])


@dataclass_json
@dataclass
class TrojanOCO:
    @dataclass_json
    @dataclass
    class ServerObject:
        address: str
        port: int
        password: str
        level: Optional[int] = None
        email: Optional[str] = None

        @staticmethod
        def from_url(url: ParseResult, queries: Queries) -> 'TrojanOCO.ServerObject':
            return TrojanOCO.ServerObject(
                address=url.hostname,
                port=url.port,
                password=url.username,
            )

    servers: Optional[List[ServerObject]] = None

    @staticmethod
    def from_url(url: ParseResult, queries: Queries) -> 'TrojanOCO':
        return TrojanOCO(servers=[TrojanOCO.ServerObject.from_url(url, queries)])


@dataclass_json
@dataclass
class VmessOCO:
    @dataclass_json
    @dataclass
    class ServerObject:
        address: str
        port: int

        @dataclass_json
        @dataclass
        class UserObject:
            id: str
            alterId: Optional[int] = None
            security: Optional[str] = 'auto'
            level: Optional[int] = None

            @staticmethod
            def from_v2_dict(v2_dict: Dict[AnyStr, AnyStr]) -> 'VmessOCO.ServerObject.UserObject':
                return VmessOCO.ServerObject.UserObject(
                    id=v2_dict['id'],
                    alterId=int(v2_dict.get('aid')) if v2_dict.get('aid') else None,
                    security=v2_dict.get('scy'),
                )

        users: Optional[List[UserObject]] = None

        @staticmethod
        def from_v2_dict(v2_dict: Dict[AnyStr, AnyStr]) -> 'VmessOCO.ServerObject':
            return VmessOCO.ServerObject(
                address=v2_dict['add'],
                port=int(v2_dict['port']),
                users=[VmessOCO.ServerObject.UserObject.from_v2_dict(v2_dict)]
            )

    vnext: Optional[List[ServerObject]] = None

    @staticmethod
    def from_v2_dict(v2_dict: Dict[AnyStr, AnyStr]) -> 'VmessOCO':
        return VmessOCO(vnext=[VmessOCO.ServerObject.from_v2_dict(v2_dict)])


@dataclass_json
@dataclass
class ShadowsocksOCO:
    @dataclass_json
    @dataclass
    class ServerObject:
        address: str
        port: int
        method: str
        password: str
        level: Optional[int] = None
        email: Optional[str] = None

        @staticmethod
        def from_url(url: ParseResult, queries: Queries) -> 'ShadowsocksOCO.ServerObject':
            auth = base64.standard_b64decode(url.username).decode().split(':', 2)
            return ShadowsocksOCO.ServerObject(
                address=url.hostname,
                port=url.port,
                method=auth[0] if len(auth) == 2 else '',
                password=auth[1] if len(auth) == 2 else '',
            )

    servers: Optional[List[ServerObject]] = None

    @staticmethod
    def from_url(url: ParseResult, queries: Queries) -> 'ShadowsocksOCO':
        return ShadowsocksOCO(servers=[ShadowsocksOCO.ServerObject.from_url(url, queries)])


@dataclass_json
@dataclass
class SocksOCO:
    version: Optional[str] = '5'

    @dataclass_json
    @dataclass
    class ServerObject:
        address: str
        port: int

        @dataclass_json
        @dataclass
        class UserObject:
            user: Optional[AnyStr] = None
            pass_: Optional[AnyStr] = field(metadata=config(field_name='pass'), default=None)
            level: Optional[int] = None

            @staticmethod
            def from_url(url: ParseResult, queries: Queries) -> Optional['SocksOCO.ServerObject.UserObject']:
                if not url.username:
                    return
                auth = base64.standard_b64decode(url.username).decode().split(':', 2)
                return SocksOCO.ServerObject.UserObject(
                    user=auth[0] if len(auth) == 2 else '',
                    pass_=auth[1] if len(auth) == 2 else '',
                )

        users: Optional[List[UserObject]] = None

        @staticmethod
        def from_url(url: ParseResult, queries: Queries) -> 'SocksOCO.ServerObject':
            user = SocksOCO.ServerObject.UserObject.from_url(url, queries)
            return SocksOCO.ServerObject(
                address=url.hostname,
                port=url.port,
                users=[user] if user else None
            )

    servers: Optional[List[ServerObject]] = None

    @staticmethod
    def from_url(url: ParseResult, queries: Queries) -> 'SocksOCO':
        return SocksOCO(servers=[SocksOCO.ServerObject.from_url(url, queries)])


@dataclass_json
@dataclass
class OutboundObject:
    protocol: AnyStr
    tag: Optional[AnyStr] = None
    settings: Optional[Union[VlessOCO, TrojanOCO, VmessOCO, ShadowsocksOCO, SocksOCO]] = None
    streamSettings: Optional[StreamSettings] = None

    @staticmethod
    def from_url(url: Union[AnyStr, ParseResult]) -> 'OutboundObject':
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        queries = Queries(parse_qs(url.query))
        if url.scheme == 'vless':
            oo = OutboundObject(
                protocol='vless',
                tag=unquote(url.fragment),
                settings=VlessOCO.from_url(url, queries),
                streamSettings=StreamSettings.from_queries(queries)
            )
        elif url.scheme == 'trojan':
            # TLS 默认启用
            if 'security' not in queries:
                queries['security'] = ['tls']
            oo = OutboundObject(
                protocol='trojan',
                tag=unquote(url.fragment),
                settings=TrojanOCO.from_url(url, queries),
                streamSettings=StreamSettings.from_queries(queries)
            )
        elif url.scheme == 'ss':
            oo = OutboundObject(
                protocol='shadowsocks',
                tag=unquote(url.fragment),
                settings=ShadowsocksOCO.from_url(url, queries),
                streamSettings=StreamSettings.from_queries(queries)
            )
        elif url.scheme == 'vmess':
            v2_dict = json.loads(base64.standard_b64decode(url.netloc))
            oo = OutboundObject(
                protocol='vmess',
                tag=v2_dict.get('ps'),
                settings=VmessOCO.from_v2_dict(v2_dict),
                streamSettings=StreamSettings.from_v2_dict(v2_dict)
            )
        elif url.scheme == 'socks':
            oo = OutboundObject(
                protocol='socks',
                tag=unquote(url.fragment),
                settings=SocksOCO.from_url(url, queries),
                streamSettings=StreamSettings.from_queries(queries)
            )
        else:
            raise ConvertError('unexpected schema: {}'.format())

        return oo


@dataclass_json
@dataclass
class V2RayConfig:
    outbounds: Optional[List[OutboundObject]] = None


def cleandict(d):
    if isinstance(d, dict):
        return {k: cleandict(v) for k, v in d.items() if v is not None}
    elif isinstance(d, list):
        return [cleandict(v) for v in d]
    else:
        return d


def to_json(obj: Any, patchs: List[AnyStr]):
    _dict = obj.to_dict()

    if patchs:
        from jsonpath_ng import parse, JSONPath
        for _item in patchs:
            _json_path, _value = _item.split('=', 2)
            if not _json_path or not _value:
                continue

            jsonpath_expr: JSONPath = parse(_json_path)
            jsonpath_expr.update(_dict, json.loads(_value))

    return json.dumps(cleandict(_dict), indent=4, ensure_ascii=False)


def parse_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', required=True, help='The input, can be subscribe url, file or share url.')
    parser.add_argument('-o', '--output', default='-', help='Output file or folder.')
    parser.add_argument('--multi-files', action='store_true', help='Generate a separate file for each entry.')
    parser.add_argument('--patch', dest='patchs', nargs='*',
                        help='<JSON_PATH>=<VALUE>. Patch v2ray config by JsonPath.')
    return parser.parse_args()


def main():
    args = parse_args()

    if args.input.startswith('http://') or args.input.startswith('https://'):
        resp = requests.get(args.input)
        resp.raise_for_status()
        sub_urls = base64.standard_b64decode(resp.text).decode().splitlines()
    elif args.input.startswith('vmess://') \
            or args.input.startswith('vless://') \
            or args.input.startswith('trojan://') \
            or args.input.startswith('ss://') \
            or args.input.startswith('socks://'):
        sub_urls = [args.input]
    elif os.path.isfile(args.input):
        with open(args.input) as fd:
            sub_urls = fd.readlines()
    else:
        logging.fatal('unknown input: {}'.format(args.input))
        exit(1)

    if args.multi_files and not os.path.isdir(args.output):
        logging.fatal('-o=%s is not a dir or not existed.', args.output)
        exit(1)

    oos = [OutboundObject.from_url(url) for url in sub_urls]

    _to_json = partial(to_json, patchs=args.patchs)

    if args.multi_files:
        for oo in oos:
            if not oo.tag:
                logging.warning('{} tag is empty, skip'.format(oo))
                continue
            with open(os.path.join(args.output, oo.tag)+'.json', 'w+', encoding='utf-8') as fd:
                cfg = V2RayConfig(outbounds=[oo])
                fd.write(_to_json(cfg))
    elif args.output == '-':
        print(_to_json(V2RayConfig(outbounds=oos)))
    else:
        with open(args.output, 'w+', encoding='utf-8') as fd:
            fd.write(_to_json(V2RayConfig(outbounds=oos)))


if __name__ == '__main__':
    main()
