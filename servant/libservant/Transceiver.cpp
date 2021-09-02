/**
 * Tencent is pleased to support the open source community by making Tars available.
 *
 * Copyright (C) 2016THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use this file except 
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software distributed 
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 * specific language governing permissions and limitations under the License.
 */

#include "servant/Transceiver.h"
#include "servant/AdapterProxy.h"
#include "servant/Application.h"
#include "servant/RemoteLogger.h"
#include "servant/ProxyInfo.h"

#if TARS_SSL
#include "util/tc_openssl.h"
#endif

namespace tars
{

static const int BUFFER_SIZE = 16 * 1024;

///////////////////////////////////////////////////////////////////////
Transceiver::Transceiver(AdapterProxy * pAdapterProxy,const EndpointInfo &ep)
: _adapterProxy(pAdapterProxy)
, _ep(ep)
, _fd(-1)
, _connStatus(eUnconnected)
, _conTimeoutTime(0)
, _authState(AUTH_INIT)
, _sendBuffer(this)
, _recvBuffer(this)
{
    _fdInfo.iType = FDInfo::ET_C_NET;
    _fdInfo.p     = (void *)this;
}

Transceiver::~Transceiver()
{
    close();


}

void Transceiver::checkTimeout()
{
    if(eConnecting == _connStatus && TNOWMS > _conTimeoutTime)
    {
        //链接超时
        TLOGERROR("[Transceiver::checkTimeout ep:"<<_adapterProxy->endpoint().desc()<<" , connect timeout]"<<endl);
        _adapterProxy->setConTimeout(true);
        close();
    }
}

bool Transceiver::isSSL() const 
{ 
    return _adapterProxy->endpoint().type() == TC_Endpoint::SSL;
}

void Transceiver::reconnect()
{
    connect();
}

void Transceiver::connect()
{
    if(isValid())
    {
        return;
    }

    if(_connStatus == eConnecting || _connStatus == eConnected)
    {
        return;
    }

	_proxyPointer = _adapterProxy->getObjProxy()->getRootServantProxy()->getProxyInfo();
    
	if(_proxyPointer)
	{
		_ep.setProxyEndpoint(_proxyPointer->getEndpoint());
	}

    //每次连接前都重新解析一下地址, 避免dns变了!
    _ep.parseConnectAddress();

    if (_ep.type() == TC_Endpoint::UDP)
    {
        _fd = NetworkUtil::createSocket(true, false, _ep.isConnectIPv6());

        _connStatus = eConnected;

        _adapterProxy->getObjProxy()->getCommunicatorEpoll()->addFd(_fd, &_fdInfo, EPOLLIN | EPOLLOUT);
    }
    else
    {
	    _fd = NetworkUtil::createSocket(false, false, _ep.isConnectIPv6());

        _adapterProxy->getObjProxy()->getCommunicatorEpoll()->addFd(_fd, &_fdInfo, EPOLLIN | EPOLLOUT);

        socklen_t len = _ep.isIPv6() ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        bool bConnected = NetworkUtil::doConnect(_fd, _ep.connectAddrPtr(), len);
        if(bConnected)
        {
            setConnected();
        }
        else
        {
            _connStatus     = Transceiver::eConnecting;
            _conTimeoutTime = TNOWMS + _adapterProxy->getConTimeout();
        }
    }

    TLOGTARS("[Transceiver::connect obj:" << _adapterProxy->getObjProxy()->name()
        << ",connect:" << _ep.getConnectEndpoint()->toString() << ", fd:" << _fd << "]" << endl);

    std::cout << "[Transceiver::connect obj:" << _adapterProxy->getObjProxy()->name()
        << ",connect:" << _ep.getConnectEndpoint()->toString() << ", fd:" << _fd << "]" << endl;

    // //设置网络qos的dscp标志
    // if(0 != _ep.qos())
    // {
    //     int iQos=_ep.qos();
    //     ::setsockopt(fd,SOL_IP,IP_TOS,&iQos,sizeof(iQos));
    // }

    //设置套接口选项
    vector<SocketOpt> &socketOpts = _adapterProxy->getObjProxy()->getSocketOpt();
    for(size_t i=0; i<socketOpts.size(); ++i)
    {
        if(setsockopt(_fd,socketOpts[i].level,socketOpts[i].optname, (const char*)socketOpts[i].optval,socketOpts[i].optlen) == -1)
        {
            TLOGERROR("[setsockopt error:" << TC_Exception::parseError(TC_Exception::getSystemCode()) 
                << ",objname:" << _adapterProxy->getObjProxy()->name() 
                << ",desc:" << _ep.getConnectEndpoint()->toString()
                << ",fd:" << _fd
                << ",level:" <<  socketOpts[i].level
                << ",optname:" << socketOpts[i].optname
                << ",optval:" << socketOpts[i].optval
                <<"    ]"<< endl);
        }
    }
}

void Transceiver::setConnected()
{
    _connStatus = eConnected;
    _adapterProxy->setConTimeout(false);
    _adapterProxy->addConnExc(false);

	TLOGTARS("[tcp setConnected, " << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << "]" << endl);
	std::cout << "[tcp setConnected, " << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << "]" << endl;

	if(_proxyPointer)
	{
		connectProxy();
	}
	else
	{
		onSetConnected();
	}
}

void Transceiver::onSetConnected()
{
	onConnect();

	if(_adapterProxy->getObjProxy()->getPushCallback())
	{
		_adapterProxy->getObjProxy()->getPushCallback()->onConnect(*_ep.getConnectEndpoint());
	}

	_adapterProxy->onConnect();
}

void Transceiver::onConnect()
{
	doAuthReq();
}

void Transceiver::connectProxy()
{
	assert(_proxyPointer);

	vector<char> buff;

	_proxyPointer->sendProxyPacket(buff, _ep.getEndpoint());

    TLOGTARS("[Transceiver::connectProxy, size:" << buff.size() << ", proxy:" << _ep.getConnectEndpoint()->toString() << endl);
    std::cout << "[Transceiver::connectProxy, size:" << buff.size() << ", proxy:" << _ep.getConnectEndpoint()->toString() << endl;

	_sendBuffer.addBuffer(buff);

	int ret = doRequest();
    if (!isValid()) 
    {
        TLOGERROR("[Transceiver::connectProxy failed sendRequest to proxy, ret:" << ret << endl);
    }
}

int Transceiver::doCheckProxy(const char *buff, size_t length)
{
	if(!_proxyPointer || _proxyPointer->isSuccess())
		return 0;

	bool succ = _proxyPointer->recvProxyPacket(buff, length);
    if(!succ)
    {
    	close();
        return -1;
    }

	if(!_proxyPointer->isSuccess())
	{
		connectProxy();
	}
	else
	{
		TLOGTARS("[Transceiver::connectProxy, succ]" << endl);

		onSetConnected();
	}

	return 1;
}

void Transceiver::doAuthReq()
{
    ObjectProxy* obj = _adapterProxy->getObjProxy();

    TLOGTARS("[Transceiver::doAuthReq obj:" << obj->name() << ", auth type:" << etos((AUTH_TYPE)_adapterProxy->endpoint().authType()) << endl);

    if (_adapterProxy->endpoint().authType() == AUTH_TYPENONE)
    {
        _authState = AUTH_SUCC;
        TLOGTARS("[Transceiver::doAuthReq doInvoke obj:" << obj->name() << ", auth type:" << etos((AUTH_TYPE)_adapterProxy->endpoint().authType()) << endl);
        std::cout << "[Transceiver::doAuthReq doInvoke obj:" << obj->name() << ", auth type:" << etos((AUTH_TYPE)_adapterProxy->endpoint().authType()) << endl;
        _adapterProxy->doInvoke(true);
    }
    else
    {
        TLOGTARS("[Transceiver::doAuthReq doInvoke obj:" << obj->name() << ", auth type:" << etos((AUTH_TYPE)_adapterProxy->endpoint().authType()) << endl);

        BasicAuthInfo basic;
        basic.sObjName      = obj->name();
        basic.sAccessKey    = obj->getCommunicatorEpoll()->getCommunicator()->getServantProperty(obj->name(), "accesskey");
        basic.sSecretKey    = obj->getCommunicatorEpoll()->getCommunicator()->getServantProperty(obj->name(), "secretkey");

        this->sendAuthData(basic);
    }
}

void Transceiver::finishInvoke(shared_ptr<ResponsePacket> &rsp)
{
	if (_adapterProxy->endpoint().authType() == AUTH_TYPELOCAL && _authState != AUTH_SUCC)
	{
		std::string ret(rsp->sBuffer.begin(), rsp->sBuffer.end());
		tars::AUTH_STATE tmp = AUTH_SUCC;
		tars::stoe(ret, tmp);
		tars::AUTH_STATE newstate = tmp;

		TLOGTARS("[Transceiver::finishInvoke state: " << etos(_authState) << " -> " << etos(newstate) << endl);
		std::cout << "[Transceiver::finishInvoke state: " << etos(_authState) << " -> " << etos(newstate) << endl;
		setAuthState(newstate);

		if (newstate == AUTH_SUCC)
		{
			// flush old buffered msg when auth is not complete
			_adapterProxy->doInvoke(true);
		}
		else
		{
			TLOGERROR("[Transceiver::finishInvoke newstate: " << etos(newstate) << ", error close!" << endl);
			close();
		}

		return;
	}
	_adapterProxy->finishInvoke(rsp);
}

bool Transceiver::sendAuthData(const BasicAuthInfo& info)
{
    assert (_authState != AUTH_SUCC);

    ObjectProxy* objPrx = _adapterProxy->getObjProxy();

    // 走框架的AK/SK认证
    std::string out = tars::defaultCreateAuthReq(info);

    const int kAuthType = 0x40;
    RequestPacket request;
    request.sFuncName       = "tarsInnerAuthServer";
    request.sServantName    = "authServant";
    request.iVersion        = TARSVERSION;
    request.iRequestId      = 1;
    request.cPacketType     = TARSNORMAL;
    request.iMessageType    = kAuthType;
    request.sBuffer.assign(out.begin(), out.end());


	_sendBuffer.addBuffer(objPrx->getProxyProtocol().requestFunc(request, this));


	TLOGTARS("[sendAuthData:" << objPrx->name() << " len: " << _sendBuffer.getBufferLength() << endl);

	int ret = doRequest();
    if (!isValid()) 
    {
        TLOGERROR("[Transceiver::sendAuthData failed sendRequest for Auth, ret:" << ret << endl);
        return false;
    }

    return true;
}

void Transceiver::close(bool destructor )
{
    if(!isValid()) return;

    if(_proxyPointer)
    {
	    _proxyPointer->reset();
    }

    _adapterProxy->getObjProxy()->getCommunicatorEpoll()->delFd(_fd,&_fdInfo, 0);

    TLOGTARS("[Transceiver::close fd:" << _fd << "]" << endl);

    NetworkUtil::closeSocketNoThrow(_fd);

    _connStatus = eUnconnected;

    _fd = -1;

	_sendBuffer.clearBuffers();

	_recvBuffer.clearBuffers();

    _authState = AUTH_INIT;

	//如果从析构函数调用close，则不走以下流程
    if (!destructor)
    {
        if (_adapterProxy->getObjProxy()->getPushCallback())
        {
            _adapterProxy->getObjProxy()->getPushCallback()->onClose(*_ep.getConnectEndpoint());
        }

        int second = _adapterProxy->getObjProxy()->reconnect();
        if (second > 0) 
        {
            int64_t nextTryConnectTime = TNOWMS + second * 1000;
            _adapterProxy->getObjProxy()->getCommunicatorEpoll()->reConnect(nextTryConnectTime, this);
            TLOGTARS("[trans close:" << _adapterProxy->getObjProxy()->name() << "," << _ep.getConnectEndpoint()->toString() << ", reconnect:" << second << "]" << endl);
        }
    }
}

int Transceiver::doRequest()
{
    std::cout << "Transceiver::doRequest" << endl;
    if(!isValid()) return -1;

	//buf不为空,先发送buffer的内容
    while(!_sendBuffer.empty())
    {
    	auto data = _sendBuffer.getBufferPointer();
    	assert(data.first != NULL && data.second != 0);
        TLOGTARS("Transceiver::doRequest send data.first:" << data.first << " data.second:" << data.second << endl);
        std::cout << "Transceiver::doRequest send data.first:" << data.first << " content:" << *(data.first) << " data.second:" << data.second << endl;
        int iRet = this->send(data.first, (uint32_t) data.second, 0);

        if (iRet < 0)
        {
            return -2;
        }

	    _sendBuffer.moveHeader(iRet);
    }

	//取adapter里面积攒的数据
    if(_sendBuffer.empty()) {
        std::cout << "Transceiver::doRequest _adapterProxy->doInvoke(false)" << endl;
        _adapterProxy->doInvoke(false);
    }

    return 0;
}

int Transceiver::sendRequest(const shared_ptr<TC_NetWorkBuffer::Buffer> &buff)
{
    //空数据 直接返回成功
    if(buff->empty()) {
	    return eRetOk;
    }

    // assert(_sendBuffer.empty());
    //buf不为空, 表示之前的数据还没发送完, 直接返回失败, 等buffer可写了,epoll会通知写事件
    if(!_sendBuffer.empty()) {
        //不应该运行到这里
        TLOGTARS("[Transceiver::sendRequest should not happened, not empty obj: " << _adapterProxy->getObjProxy()->name() << endl);
	    return eRetNotSend;
    }

    if(eConnected != _connStatus)
    {
        TLOGTARS("[Transceiver::sendRequest not connected: " << _adapterProxy->getObjProxy()->name() << endl);
        return eRetNotSend;
    }

	if(_proxyPointer && !_proxyPointer->isSuccess()) {
        TLOGTARS("[Transceiver::sendRequest proxy not ok: " << _adapterProxy->getObjProxy()->name() << endl);
		return eRetNotSend;
	}

    if (_authState != AUTH_SUCC)
    {
        TLOGTARS("[Transceiver::sendRequest need auth: " << _adapterProxy->getObjProxy()->name() << endl);
        return eRetNotSend; // 需要鉴权但还没通过，不能发送非认证消息
    }
    TLOGTARS("[Transceiver::sendRequest _sendBuffer.addBuffer(buff)  _adapterProxy->getObjProxy()->name():" << _adapterProxy->getObjProxy()->name() << endl);
    std::cout << "[Transceiver::sendRequest _sendBuffer.addBuffer(buff)  _adapterProxy->getObjProxy()->name():" << _adapterProxy->getObjProxy()->name() << endl;
    _sendBuffer.addBuffer(buff);

    do
    {
        auto data = _sendBuffer.getBufferPointer();

        std::cout << "[Transceiver::sendRequest send data.first:" << data.first << " data.second:" << data.second << endl;
        int iRet = this->send(data.first, (uint32_t) data.second, 0);
        if(iRet < 0)
        {
            if(!isValid()) 
            {
                _sendBuffer.clearBuffers();
                TLOGTARS("[Transceiver::sendRequest failed eRetError: data size:" << data.second << "]" << endl);
                return eRetError;
            } 
            else
            {
                TLOGTARS("[Transceiver::sendRequest failed eRetFull]" << endl);
                return eRetFull;
            }
        }

        _sendBuffer.moveHeader(iRet);
    }
    while(!_sendBuffer.empty());

    return eRetOk;
}

//////////////////////////////////////////////////////////
TcpTransceiver::TcpTransceiver(AdapterProxy * pAdapterProxy, const EndpointInfo &ep)
: Transceiver(pAdapterProxy, ep)
{
}


int TcpTransceiver::doResponse()
{
    if(!isValid()) return -1;

	int iRet = 0;

    int recvCount = 0;
	do
    {
	    char buff[BUFFER_SIZE] = {0x00};

	    if ((iRet = this->recv(buff, BUFFER_SIZE, 0)) > 0)
	    {
		    int check = doCheckProxy(buff, iRet);
            if(check != 0)
		    {
		    	return 0;
		    }

		    TC_NetWorkBuffer *rbuf = &_recvBuffer;

		    rbuf->addBuffer(buff, iRet);

		    ++recvCount;

		    try
		    {
			    TC_NetWorkBuffer::PACKET_TYPE ret;

			    do
		        {
                    TLOGTARS("TcpTransceiver::doResponse _adapterProxy->getObjProxy()->name():" << _adapterProxy->getObjProxy()->name() << ", fd:" << _fd << " _ep.getConnectEndpoint():" << _ep.getConnectEndpoint()->toString() << endl);
                    //std::cout << "TcpTransceiver::doResponse _adapterProxy->getObjProxy()->name():" << _adapterProxy->getObjProxy()->name() << ", fd:" << _fd << " _ep.getConnectEndpoint():" << _ep.getConnectEndpoint()->toString() << endl;

                    std::thread::id tid = std::this_thread::get_id();
                    std::cout << "TcpTransceiver::doResponse thread id=" << tid << endl;
                    std::cout << "TcpTransceiver::doResponse _adapterProxy->getObjProxy()->getProxyProtocol().responseFunc  解包" << endl;

			        shared_ptr<ResponsePacket> rsp = std::make_shared<ResponsePacket>();
			        ret = _adapterProxy->getObjProxy()->getProxyProtocol().responseFunc(*rbuf, *rsp.get());

				    if (ret == TC_NetWorkBuffer::PACKET_ERR) {
					    TLOGERROR( "TcpTransceiver::doResponse PACKET_ERR," << _adapterProxy->getObjProxy()->name() << ", size:" << iRet << ", fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << endl);
					    std::cout << "TcpTransceiver::doResponse PACKET_ERR," << _adapterProxy->getObjProxy()->name() << ", size:" << iRet << ", fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << endl;
					    close();
					    break;
				    }
				    else if (ret == TC_NetWorkBuffer::PACKET_FULL) {
                        std::cout << "TcpTransceiver::doResponse PACKET_FULL," << endl;
                        finishInvoke(rsp);
				    }
					else if (ret == TC_NetWorkBuffer::PACKET_FULL_CLOSE) {
                        std::cout << "TcpTransceiver::doResponse PACKET_FULL_CLOSE," << _adapterProxy->getObjProxy()->name() << ", size:" << iRet << ", fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << endl;
						close();
	                    finishInvoke(rsp);
						break;
					}
				    else {
					    break;
				    }

			    }
			    while (ret == TC_NetWorkBuffer::PACKET_FULL);

			    //接收的数据小于buffer大小, 内核会再次通知你
			    if(iRet < BUFFER_SIZE)
			    {
				    break;
			    }

			    //收包太多了, 中断一下, 释放线程给send等
			    if (recvCount >= 100 && isValid()) {
				    _adapterProxy->getObjProxy()->getCommunicatorEpoll()->modFd(_fd, &_fdInfo, EPOLLIN | EPOLLOUT);
				    break;
			    }
		    }
		    catch (exception & ex) {
			    TLOGERROR("[tcp doResponse," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << ","
			                                      << _ep.getConnectEndpoint()->toString() << ",tcp recv decode error:" << ex.what() << endl);

			    close();
		    }
		    catch (...) {
			    TLOGERROR("[tcp doResponse," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << ","
			                                      << _ep.getConnectEndpoint()->toString() << ",tcp recv decode error." << endl);

			    close();
		    }
	    }
    }
    while (iRet>0);

//    TLOGTARS("[tcp doResponse, " << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << ", all recvbuf:" << _recvBuffer.getBufferLength() << "]" << endl);

	return 0;
}

int TcpTransceiver::send(const void* buf, uint32_t len, uint32_t flag)
{
    //只有是连接状态才能收发数据
    if(eConnected != _connStatus)
        return -1;

	int iRet = ::send(_fd, (const char*)buf, len, flag);

	if (iRet < 0 && !TC_Socket::isPending())
    {
        TLOGTARS("[tcp send," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString()
            << ",fail! errno:" << TC_Exception::getSystemCode() << "," 
            << TC_Exception::parseError(TC_Exception::getSystemCode()) << ",close]" << endl);

        close();

        return iRet;
    }
 
    TLOGTARS("[TcpTransceiver::send tcp send," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << "," 
        << _ep.getConnectEndpoint()->toString() << ",len:" << iRet <<"]" << endl);

    std::cout << "[TcpTransceiver::send tcp send===》," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << ","
        << _ep.getConnectEndpoint()->toString() << ",len:" << iRet  << " buf:" << (char*)buf << endl;
    printf("printf buf:%s\n", (char*)buf);
    for (int i =0;i<iRet;++i)
    {
        std::cout << *((char*)(buf + i));
    }
    std::cout << endl;

    return iRet;
}

int TcpTransceiver::recv(void* buf, uint32_t len, uint32_t flag)
{
    //只有是连接状态才能收发数据
    if(eConnected != _connStatus)
        return -1;

    int iRet = ::recv(_fd, (char*)buf, len, flag);

	if (iRet == 0 || (iRet < 0 && !TC_Socket::isPending()))
    {
        TLOGTARS("[TcpTransceiver::recv tcp recv, " << _adapterProxy->getObjProxy()->name()
                << ",fd:" << _fd << ", " << _ep.getConnectEndpoint()->toString() <<",ret " << iRet
                << ", fail! errno:" << TC_Exception::getSystemCode() << "," << TC_Exception::parseError(TC_Exception::getSystemCode()) << ",close]" << endl);

        close();

        return 0;
    }

 
    TLOGTARS("[TcpTransceiver::recv tcp recv," << _adapterProxy->getObjProxy()->name()
            << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << ",ret:" << iRet << "]" << endl);

    std::cout << "[TcpTransceiver::recv tcp recv《===," << _adapterProxy->getObjProxy()->name()
        << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << ",ret:" << iRet << " buf:" << (char*)buf << endl;
    printf("printf buf:%s\n", (char*)buf);
    for (int i = 0; i < iRet; ++i)
    {
        std::cout << *((char*)(buf + i));
    }
    std::cout << endl;

    return iRet;
}

/////////////////////////////////////////////////////////////////
UdpTransceiver::UdpTransceiver(AdapterProxy * pAdapterProxy, const EndpointInfo &ep)
: Transceiver(pAdapterProxy, ep)
,_pRecvBuffer(NULL)
{
    // UDP不支持鉴权
    _authState = AUTH_SUCC;

    if(!_pRecvBuffer)
    {
        _pRecvBuffer = new char[DEFAULT_RECV_BUFFERSIZE];
        if(!_pRecvBuffer)
        {
            throw TC_Exception("obj: '" + _adapterProxy->getObjProxy()->name() + "' malloc udp receive buffer fail");
        }
    }

}

UdpTransceiver::~UdpTransceiver()
{
    if(_pRecvBuffer)
    {
        delete _pRecvBuffer;
        _pRecvBuffer = NULL;
    }
}


int UdpTransceiver::doResponse()
{
    if(!isValid()) return -1;

    int recv = 0;

//    done.clear();
    do
    {
        if ((recv = this->recv(_pRecvBuffer, DEFAULT_RECV_BUFFERSIZE, 0)) > 0)
        {
            TLOGTARS("[udp doResponse, " << _adapterProxy->getObjProxy()->name()
                    << ",fd:" << _fd << ",recvbuf:" << recv << "]" << endl);

	        _recvBuffer.clearBuffers();
            _recvBuffer.addBuffer(_pRecvBuffer, recv);

            try
            {
	            shared_ptr<ResponsePacket> rsp = std::make_shared<ResponsePacket>();

                TC_NetWorkBuffer::PACKET_TYPE ret;

                ret = _adapterProxy->getObjProxy()->getProxyProtocol().responseFunc(_recvBuffer, *rsp.get());

                if(ret == TC_NetWorkBuffer::PACKET_ERR || ret == TC_NetWorkBuffer::PACKET_LESS)
                {
                    TLOGERROR("[udp doResponse," << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << ",tcp recv decode error, ret:" << ret << endl);
                    break;
                }
                else
                {
	                finishInvoke(rsp);
                }
            }
            catch (exception &ex)
            {
                TLOGERROR("[udp doResponse, " << _adapterProxy->getObjProxy()->name()
                        << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString()
                        << ", udp recv decode error:" << ex.what() << endl);
            }
            catch (...)
            {
                TLOGERROR("[udp doResponse, " << _adapterProxy->getObjProxy()->name()
                        << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString()
                        << ", udp recv decode error." << endl);
            }
        }
    }
    while (recv > 0);

    return 0;
}

int UdpTransceiver::send(const void* buf, uint32_t len, uint32_t flag)
{
    if(!isValid()) return -1;

	socklen_t addrlen = _ep.isIPv6() ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	int iRet=::sendto(_fd, (const char*)buf, len, flag, _ep.connectAddrPtr(), addrlen);

	if (iRet<0)
    {
        if(!TC_Socket::isPending())
        {
            TLOGERROR("[udp send " << _adapterProxy->getObjProxy()->name()
                    << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << ", fail! errno:"
                    << TC_Exception::getSystemCode() << "," 
                    << TC_Exception::parseError(TC_Exception::getSystemCode()) << ",close]" << endl);

			close();

            return iRet;
        }
        iRet=0;
    }
    else if(iRet>0 && iRet != (int)len)
    {
        TLOGERROR("[udp send, " << _adapterProxy->getObjProxy()->name()
                << ",fd:" << _fd << "," << _ep.getConnectEndpoint()->toString() << ", send error."
                << ", len:" << len << ", sendLen:" << iRet << endl);
        //udp只发一次 发送一半也算全部发送成功
        iRet = len;
    }
    return iRet;
}

int UdpTransceiver::recv(void* buf, uint32_t len, uint32_t flag)
{
    if(!isValid()) return -1;

    int iRet = ::recvfrom(_fd, (char*)buf, len, flag, NULL, NULL); //need check from_ip & port

    if (iRet < 0  && !TC_Socket::isPending())
    {
        TLOGERROR("[udp recv " << _adapterProxy->getObjProxy()->name() << ",fd:" << _fd << ","
            << _ep.getConnectEndpoint()->toString() << ", fail! errno:" << TC_Exception::getSystemCode() << ","
            << TC_Exception::parseError(TC_Exception::getSystemCode()) << ",close]" << endl);

		close();

		return 0;
    }
    return iRet;
}

/////////////////////////////////////////////////////////////////
}
