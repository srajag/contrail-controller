/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>

#include "base/logging.h"
#include "cmn/agent_cmn.h"
#include "cmn/agent_param.h"
#include "tap_interface.h"
#include "sandesh/sandesh_types.h"
#include "sandesh/sandesh.h"
#include "sandesh/sandesh_trace.h"
#include "pkt/pkt_types.h"
#include "pkt_init.h"

#define TUN_INTF_CLONE_DEV "/dev/net/tun"

#define TAP_TRACE(obj, ...)                                              \
do {                                                                     \
    Tap##obj::TraceMsg(PacketTraceBuf, __FILE__, __LINE__, __VA_ARGS__); \
} while (false)                                                          \

using namespace boost::asio;

///////////////////////////////////////////////////////////////////////////////

const char *ExceptionPktSocket::kAgentSocketPath = "/tmp/agent_pkt0";
const char *ExceptionPktSocket::kVrouterSocketPath =
                "/tmp/dpdk_pkt0";

ExceptionPktInterface::ExceptionPktInterface(Agent *agent,
    const std::string &name, boost::asio::io_service &io,
    PktReadCallback cb) : agent_(agent), name_(name),
    read_buf_(NULL), pkt_handler_(cb) {
    memset(mac_address_, 0, sizeof(mac_address_));
}

ExceptionPktInterface::~ExceptionPktInterface() { 
}

void ExceptionPktInterface::WriteHandler(const boost::system::error_code &error,
                                         std::size_t length, uint8_t *buf) {
    if (error) {
        TAP_TRACE(Err, "Packet Tap Error <" + error.message() 
                  + "> sending packet");
    }
    delete [] buf;
}

void ExceptionPktInterface::ReadHandler(const boost::system::error_code &error,
                              std::size_t length) {
    if (!error) {
        pkt_handler_(read_buf_, length, kMaxPacketSize);
    } else  {
        TAP_TRACE(Err, 
                  "Packet Tap Error <" + error.message() + "> reading packet");
        if (error == boost::system::errc::operation_canceled) {
            return;
        }
    }
    AsyncRead();
}

TapInterface::TapInterface(Agent *agent,
    const std::string &name, boost::asio::io_service &io,
    PktReadCallback cb):
    ExceptionPktInterface(agent, name, io, cb), tap_fd_(-1), stream_(io) {
}

void TapInterface::AsyncWrite(uint8_t *buf, std::size_t len) {
    stream_.async_write_some(boost::asio::buffer(buf, len), 
                             boost::bind(&TapInterface::WriteHandler, this,
                             boost::asio::placeholders::error,
                             boost::asio::placeholders::bytes_transferred,
                             buf));
}

void TapInterface::AsyncRead() {
    read_buf_ = new uint8_t[kMaxPacketSize];
    stream_.async_read_some(
            boost::asio::buffer(read_buf_, kMaxPacketSize), 
            boost::bind(&TapInterface::ReadHandler, this,
                        boost::asio::placeholders::error,
                        boost::asio::placeholders::bytes_transferred));
}

void TapInterface::CreateTunnelIntf() {
    if (name_ != agent_->pkt_interface_name()) {
        return;
    }

    if ((tap_fd_ = open(TUN_INTF_CLONE_DEV, O_RDWR)) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> opening tap-device");
        assert(0);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name_.c_str(), IF_NAMESIZE);
    if (ioctl(tap_fd_, TUNSETIFF, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> creating " << name_ << "tap-device");
        assert(0);
    }

    // We dont want the fd to be inherited by child process such as
    // virsh etc... So, close tap fd on fork.
    if (fcntl(tap_fd_, F_SETFD, FD_CLOEXEC) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " <<
                strerror(errno) << "> setting fcntl on " << name_ );
        assert(0);
    }

    if (ioctl(tap_fd_, TUNSETPERSIST, 0) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> making tap interface non-persistent");
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name_.c_str(), IF_NAMESIZE);
    if (ioctl(tap_fd_, SIOCGIFHWADDR, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << 
                "> retrieving MAC address of the tap interface");
        assert(0);
    }
    memcpy(mac_address_, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    int raw_;
    if ((raw_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> creating socket");
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name_.data(), IF_NAMESIZE);
    if (ioctl(raw_, SIOCGIFINDEX, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> getting ifindex of the tap interface");
        assert(0);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(raw_, (struct sockaddr *)&sll, 
                sizeof(struct sockaddr_ll)) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> binding the socket to the tap interface");
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name_.data(), IF_NAMESIZE);
    if (ioctl(raw_, SIOCGIFFLAGS, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> getting socket flags");
        assert(0);
    }

    ifr.ifr_flags |= IFF_UP;
    if (ioctl(raw_, SIOCSIFFLAGS, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> setting socket flags");
        assert(0);
    }

    close(raw_);
}

void TapInterface::Init() {
    CreateTunnelIntf();

    boost::system::error_code ec;
    stream_.assign(tap_fd_, ec);

    AsyncRead();
}

void TapInterface::IoShutdown() { 
    if (read_buf_) {
        delete [] read_buf_;
    }
    close(tap_fd_);
    tap_fd_ = -1;
}

ExceptionPktEthInterface::ExceptionPktEthInterface(Agent *agent,
    const std::string &name, boost::asio::io_service &io, PktReadCallback cb):
    ExceptionPktInterface(agent, name, io, cb), raw_fd_(-1), stream_(io) {
}

void ExceptionPktEthInterface::CreateRawIntf() {
    int raw_;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if ((raw_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> creating socket");
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, agent_->pkt_interface_name().c_str(), IF_NAMESIZE);
    if (ioctl(raw_, SIOCGIFINDEX, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> getting ifindex of the tap interface");
        assert(0);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(raw_, (struct sockaddr *)&sll, 
                sizeof(struct sockaddr_ll)) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> binding the socket to the tap interface");
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name_.data(), IF_NAMESIZE);
    if (ioctl(raw_, SIOCGIFFLAGS, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> getting socket flags");
        assert(0);
    }

    ifr.ifr_flags |= IFF_UP;
    if (ioctl(raw_, SIOCSIFFLAGS, (void *)&ifr) < 0) {
        LOG(ERROR, "Packet Tap Error <" << errno << ": " << 
                strerror(errno) << "> setting socket flags");
        assert(0);
    }
    raw_fd_ = raw_;
}

void ExceptionPktEthInterface::Init() {
    CreateRawIntf();

    boost::system::error_code ec;
    stream_.assign(raw_fd_, ec);
    assert(ec == 0);

    AsyncRead();
}

void ExceptionPktEthInterface::IoShutdown() { 
    if (read_buf_) {
        delete [] read_buf_;
    }
    close(raw_fd_);
    raw_fd_ = -1;
}

void ExceptionPktEthInterface::AsyncWrite(uint8_t *buf, std::size_t len) {
    stream_.async_write_some(boost::asio::buffer(buf, len), 
                             boost::bind(&ExceptionPktEthInterface::WriteHandler,
                             this, boost::asio::placeholders::error,
                             boost::asio::placeholders::bytes_transferred,
                             buf));
}

void ExceptionPktEthInterface::AsyncRead() {
    read_buf_ = new uint8_t[kMaxPacketSize];
    stream_.async_read_some(
            boost::asio::buffer(read_buf_, kMaxPacketSize), 
            boost::bind(&ExceptionPktEthInterface::ReadHandler, this,
                        boost::asio::placeholders::error,
                        boost::asio::placeholders::bytes_transferred));
}


ExceptionPktSocket::ExceptionPktSocket(Agent *agent, const std::string &name,
    boost::asio::io_service &io, PktReadCallback cb):
    ExceptionPktInterface(agent, name, io, cb),
    read_socket_(io), write_socket_(io) {
}

void ExceptionPktSocket::CreateUnixSocket() {
    unlink(kAgentSocketPath);

    boost::system::error_code ec;
    read_socket_.open();
    local::datagram_protocol::endpoint ep(kAgentSocketPath);
    read_socket_.bind(ep, ec);
    assert(ec == 0);
}

void ExceptionPktSocket::Init() {
    CreateUnixSocket();
    AsyncRead();
    StartConnectTimer();
}

void ExceptionPktSocket::IoShutdown() { 
    if (read_buf_) {
        delete [] read_buf_;
    }

    boost::system::error_code ec;
    read_socket_.close(ec);
    write_socket_.close(ec);
}

void ExceptionPktSocket::AsyncRead() {
    read_buf_ = new uint8_t[kMaxPacketSize];
    read_socket_.async_receive(
            boost::asio::buffer(read_buf_, kMaxPacketSize), 
            boost::bind(&ExceptionPktSocket::ReadHandler, this,
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
}

void ExceptionPktSocket::StartConnectTimer() {
    timer_.reset(TimerManager::CreateTimer(
                 *(agent_->event_manager()->io_service()),
                 "UnixSocketConnectTimer"));
    timer_->Start(kConnectTimeout,
                  boost::bind(&ExceptionPktSocket::OnTimeout, this));
}

bool ExceptionPktSocket::OnTimeout() {
    local::datagram_protocol::endpoint ep(kVrouterSocketPath);
    boost::system::error_code ec;
    read_socket_.connect(ep, ec);
    if (ec != 0) {
        LOG(DEBUG, "Connect error " << ec);
        return true;
    }
    connected_ = true;
    return false;
}

void ExceptionPktSocket::AsyncWrite(uint8_t *buf, std::size_t len) {
    if (connected_ == false) {
        //queue the data?
    }
    read_socket_.async_send(boost::asio::buffer(buf, len), 
                             boost::bind(&ExceptionPktSocket::WriteHandler, this,
                             boost::asio::placeholders::error,
                             boost::asio::placeholders::bytes_transferred,
                             buf));
}
