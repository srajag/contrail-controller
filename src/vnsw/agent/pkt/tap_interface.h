/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef vnsw_agent_pkt_tap_intf_hpp
#define vnsw_agent_pkt_tap_intf_hpp

#include <string>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>

// Tap Interface handler to read or write to the "pkt0" interface.
// Packets reads from the tap are given to the registered callback.
// Write to the tap interface using AsyncWrite.
class ExceptionPktInterface {
public:
    static const uint32_t kMaxPacketSize = 9060;
    typedef boost::function<void(uint8_t*, std::size_t, std::size_t)> 
        PktReadCallback;

    ExceptionPktInterface(Agent *agent, const std::string &name,
                          boost::asio::io_service &io, PktReadCallback cb);
    virtual ~ExceptionPktInterface();
    virtual void Init() = 0;
    virtual void IoShutdown() = 0;
    virtual void AsyncWrite(uint8_t *buf, std::size_t len) = 0;
    virtual void AsyncRead() = 0;
    const unsigned char *mac_address() const { return mac_address_;}

protected:
    void ReadHandler(const boost::system::error_code &err, std::size_t length);
    void WriteHandler(const boost::system::error_code &err, std::size_t length,
	                  uint8_t *buf);
    Agent *agent_;
    std::string name_;
    uint8_t *read_buf_;
    PktReadCallback pkt_handler_;
    unsigned char mac_address_[ETH_ALEN];
    DISALLOW_COPY_AND_ASSIGN(ExceptionPktInterface);
};

class TapInterface : public ExceptionPktInterface {
public:
    TapInterface(Agent *agent, const std::string &name,
                 boost::asio::io_service &io, PktReadCallback cb);
    virtual void Init();
    virtual void IoShutdown();
    virtual void AsyncWrite(uint8_t *buf, std::size_t len);
    virtual void AsyncRead();
protected:
    int tap_fd_;
    boost::asio::posix::stream_descriptor stream_;
private:
    void CreateTunnelIntf();
};

class ExceptionPktEthInterface : public ExceptionPktInterface {
public:    
    ExceptionPktEthInterface(Agent *agent, const std::string &name,
                             boost::asio::io_service &io,
                             PktReadCallback cb);
    virtual void Init();
    virtual void IoShutdown();
    virtual void AsyncWrite(uint8_t *buf, std::size_t len);
    virtual void AsyncRead();
private:
    void CreateRawIntf();
    int raw_fd_;
    boost::asio::posix::stream_descriptor stream_;
};

class ExceptionPktSocket : public ExceptionPktInterface {
public:
    static const uint32_t kConnectTimeout = 100; //100 millisecond
    static const char *kAgentSocketPath;
    static const char *kVrouterSocketPath;
    ExceptionPktSocket(Agent *agent, const std::string &name,
                       boost::asio::io_service &io,
                       PktReadCallback cb);
    virtual void Init();
    virtual void IoShutdown();
    virtual void AsyncWrite(uint8_t *buf, std::size_t len);
    virtual void AsyncRead();
private:
    void CreateUnixSocket();
    void StartConnectTimer();
    bool OnTimeout();
    bool connected_;
    boost::asio::local::datagram_protocol::socket read_socket_;
    boost::asio::local::datagram_protocol::socket write_socket_;
    boost::scoped_ptr<Timer> timer_;
};
#endif // vnsw_agent_pkt_tap_intf_hpp
