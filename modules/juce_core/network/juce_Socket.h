/*
  ==============================================================================

   This file is part of the JUCE library - "Jules' Utility Class Extensions"
   Copyright 2004-11 by Raw Material Software Ltd.

  ------------------------------------------------------------------------------

   JUCE can be redistributed and/or modified under the terms of the GNU General
   Public License (Version 2), as published by the Free Software Foundation.
   A copy of the license is included in the JUCE distribution, or can be found
   online at www.gnu.org/licenses.

   JUCE is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  ------------------------------------------------------------------------------

   To release a closed-source product which uses JUCE, commercial licenses are
   available: visit www.rawmaterialsoftware.com/juce for more information.

  ==============================================================================
*/

#ifndef __JUCE_SOCKET_JUCEHEADER__
#define __JUCE_SOCKET_JUCEHEADER__

#include "../text/juce_String.h"


//==============================================================================
/**
    A collection of helpers for Socket communication.

    @see DatagramSocket, StreamingSocket
*/
class JUCE_API Socket
{
public:
    //==============================================================================
    /** Conditional endian swaps, so that socket stuff doesn't have to be included. */
    static uint32 HostToNetworkUint32 (uint32 value);
    static uint16 HostToNetworkUint16 (uint16 value);
    static uint32 NetworkToHostUint32 (uint32 value);
    static uint16 NetworkToHostUint16 (uint16 value);

    /** Constant to indicate that the system should pick the port */
    static const uint16 anyPort;
};


//==============================================================================
/**
    A wrapper for a streaming (TCP) socket.

    This allows low-level use of sockets; for an easier-to-use messaging layer on top of
    sockets, you could also try the InterprocessConnection class.

    @see DatagramSocket, InterprocessConnection, InterprocessConnectionServer
*/
class JUCE_API  StreamingSocket
{
public:
    //==============================================================================
    /** Creates an uninitialised socket.

        To connect it, use the connect() method, after which you can read() or write()
        to it.

        To wait for other sockets to connect to this one, the createListener() method
        enters "listener" mode, and can be used to spawn new sockets for each connection
        that comes along.
    */
    StreamingSocket();

    /** Destructor. */
    ~StreamingSocket();

    //==============================================================================
    /** Binds the socket to the specified local port.

        @returns    true on success; false may indicate that another socket is already bound
                    on the same port
    */
    bool bindToPort (int localPortNumber);

    /** Tries to connect the socket to hostname:port.

        If timeOutMillisecs is 0, then this method will block until the operating system
        rejects the connection (which could take a long time).

        @returns true if it succeeds.
        @see isConnected
    */
    bool connect (const String& remoteHostname,
                  int remotePortNumber,
                  int timeOutMillisecs = 3000);

    /** True if the socket is currently connected. */
    bool isConnected() const noexcept                           { return connected; }

    /** Closes the connection. */
    void close();

    /** Returns the name of the currently connected host. */
    const String& getHostName() const noexcept                  { return hostName; }

    /** Returns the port number that's currently open. */
    int getPort() const noexcept                                { return portNumber; }

    /** True if the socket is connected to this machine rather than over the network. */
    bool isLocal() const noexcept;

    //==============================================================================
    /** Waits until the socket is ready for reading or writing.

        If readyForReading is true, it will wait until the socket is ready for
        reading; if false, it will wait until it's ready for writing.

        If the timeout is < 0, it will wait forever, or else will give up after
        the specified time.

        If the socket is ready on return, this returns 1. If it times-out before
        the socket becomes ready, it returns 0. If an error occurs, it returns -1.
    */
    int waitUntilReady (bool readyForReading,
                        int timeoutMsecs) const;

    /** Reads bytes from the socket.

        If blockUntilSpecifiedAmountHasArrived is true, the method will block until
        maxBytesToRead bytes have been read, (or until an error occurs). If this
        flag is false, the method will return as much data as is currently available
        without blocking.

        @returns the number of bytes read, or -1 if there was an error.
        @see waitUntilReady
    */
    int read (void* destBuffer, int maxBytesToRead,
              bool blockUntilSpecifiedAmountHasArrived);

    /** Writes bytes to the socket from a buffer.

        Note that this method will block unless you have checked the socket is ready
        for writing before calling it (see the waitUntilReady() method).

        @returns the number of bytes written, or -1 if there was an error.
    */
    int write (const void* sourceBuffer, int numBytesToWrite);

    //==============================================================================
    /** Puts this socket into "listener" mode.

        When in this mode, your thread can call waitForNextConnection() repeatedly,
        which will spawn new sockets for each new connection, so that these can
        be handled in parallel by other threads.

        @param portNumber       the port number to listen on
        @param localHostName    the interface address to listen on - pass an empty
                                string to listen on all addresses
        @returns    true if it manages to open the socket successfully.

        @see waitForNextConnection
    */
    bool createListener (int portNumber, const String& localHostName = String::empty);

    /** When in "listener" mode, this waits for a connection and spawns it as a new
        socket.

        The object that gets returned will be owned by the caller.

        This method can only be called after using createListener().

        @see createListener
    */
    StreamingSocket* waitForNextConnection() const;


private:
    //==============================================================================
    String hostName;
    int volatile portNumber, handle;
    bool connected, isListener;

    StreamingSocket (const String& hostname, int portNumber, int handle);

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (StreamingSocket);
};


//==============================================================================
/**
 A wrapper for a IPv4 addresses
 
 This simple wrapper is for IPv4 addresses and is primarily intended for
 use with a broadcasting DatagramSocket. It only handles IPv4 because
 IPv6 is not typically used in UDP broadcasting and multicasting applications
 since they are not generally routed outside the local network.
 
 @see DatagramSocket
 */
class JUCE_API IpAddress
{
public:
    //==============================================================================
    /** Populates a list of the IPv4 addresses of all the available network cards. */
    static void findAllIpAddresses (Array<IpAddress>& results);
    
    //==============================================================================
    /** Creates a null address (0.0.0.0). */
    IpAddress();
    
    /** Creates from a host order uint32. */
    IpAddress (uint32 addr);
    
    /** Creates from another address. */
    IpAddress (const IpAddress& other);
    
    /** Creates a copy of another address. */
    IpAddress& operator= (const IpAddress& other);
    
    /** Creates an address from a string ("1.2.3.4"). */
    explicit IpAddress (const String& addr);
    
    /** Returns a dot-separated string in the form "1.2.3.4". */
    String toString() const;
    
    /** Return as host order uint32. */
    uint32 toUint32() const noexcept;
    
    /** Return as network order uint32. */
    uint32 toNetworkUint32() const noexcept;
    
    /** Returns true if this address is ANY (0.0.0.0). */
    bool isAny() const noexcept;
    
    /** Returns true if this address is BROADCAST (255.255.255.255). */
    bool isBroadcast() const noexcept;
    
    /** Returns true if this address is LOOPBACK (127.0.0.1). */
    bool isLocal() const noexcept;

    bool operator== (const IpAddress& other) const noexcept;
    bool operator!= (const IpAddress& other) const noexcept;

    //==============================================================================
    /** IPv4 Any Address. */
    static const IpAddress any;
    static const IpAddress broadcast;
    static const IpAddress localhost;
    
    //==============================================================================
private:
    uint32 ipAddress;
};


//==============================================================================
/**
    A wrapper for a datagram (UDP) socket.

    This allows low-level use of sockets; for an easier-to-use messaging layer on top of
    sockets, you could also try the InterprocessConnection class.

    @see StreamingSocket, InterprocessConnection, InterprocessConnectionServer
*/
class JUCE_API  DatagramSocket
{
public:
    //==============================================================================
    /**
        Creates an (uninitialised) datagram socket.

        The localPortNumber is the port on which to bind this socket. If this value is 0,
        the port number is assigned by the operating system.

        To use the socket for sending, call the connect() method. This will not immediately
        make a connection, but will save the destination you've provided. After this, you can
        call read() or write().

        If enableBroadcasting is true, the socket will be allowed to send broadcast messages
        (may require extra privileges on linux)
     
        If enableReuseAddress is true, the socket will allow any bound address to be
        shared.

        To wait for other sockets to connect to this one, call waitForNextConnection().
    */
    DatagramSocket (int localPortNumber,
                    bool enableBroadcasting = false,
                    bool enableReuseAddress = false,
                    const IpAddress& localAddress = IpAddress::any);

    /** Destructor. */
    ~DatagramSocket();

    //==============================================================================
    /** Binds the socket to the specified local port.
     
        The optional localAddress can be used to bind to a specific IP.

        @returns    true on success; false may indicate that another socket is already bound
                    on the same port
    */
    bool bindToPort (int localPortNumber,
                     const IpAddress& localAddress = IpAddress::any);

    /** Add a multicast address to receive from.

        Since all DatagramSocket constructors currently bind an address you do not have to
        explicitly call the bind member before using this function.

        @returns    true on success
        @see dropMulticastMembership
    */
    bool addMulticastMembership (const IpAddress& address);

    /** Remove a multicast address to receive from.

        @returns    true on success
        @see addMulticastMembership
    */
    bool dropMulticastMembership (const IpAddress& address);

    /** Tries to connect the socket to hostname:port.

        This function does not connect in the low level sockets sense.
        Instead it resolves the remote host name and port to a low
        level sock_addr, which is then used for subsequent writes.

        So it can be called multiple times for broadcast situations, etc.

        @returns true if it succeeds.
        @see isConnected
    */
    bool connect (const String& remoteHostname,
                  int remotePortNumber,
                  int timeOutMillisecs = 3000);

    /** Connect using an IpAddress instead */
    bool connect (const IpAddress& remoteHost,
                  int remotePortNumber,
                  int timeOutMillisecs = 3000);

    /** True if the socket is currently connected. */
    bool isConnected() const noexcept                           { return connected; }

    /** Closes the connection. */
    void close();

    /** Returns the name of the currently connected host. */
    const String& getHostName() const noexcept                  { return hostName; }

    /** Returns the port number that's currently open. */
    int getPort() const noexcept                                { return portNumber; }

    /** True if the socket is connected to this machine rather than over the network. */
    bool isLocal() const noexcept;

    //==============================================================================
    /** Waits until the socket is ready for reading or writing.

        If readyForReading is true, it will wait until the socket is ready for
        reading; if false, it will wait until it's ready for writing.

        If the timeout is < 0, it will wait forever, or else will give up after
        the specified time.

        If the socket is ready on return, this returns 1. If it times-out before
        the socket becomes ready, it returns 0. If an error occurs, it returns -1.
    */
    int waitUntilReady (bool readyForReading,
                        int timeoutMsecs) const;

    /** Reads bytes from the socket.

        If blockUntilSpecifiedAmountHasArrived is true, the method will block until
        maxBytesToRead bytes have been read, (or until an error occurs). If this
        flag is false, the method will return as much data as is currently available
        without blocking.

        @returns the number of bytes read, or -1 if there was an error.
        @see waitUntilReady
    */
    int read (void* destBuffer, int maxBytesToRead,
              bool blockUntilSpecifiedAmountHasArrived);

    /** Writes bytes to the socket from a buffer.

        Note that this method will block unless you have checked the socket is ready
        for writing before calling it (see the waitUntilReady() method).

        @returns the number of bytes written, or -1 if there was an error.
    */
    int write (const void* sourceBuffer, int numBytesToWrite);
     

    //==============================================================================
    /** This waits for incoming data to be sent, and returns a socket that can be used
        to read it.

        The object that gets returned is owned by the caller, and can't be used for
        sending, but can be used to read the data.
    */
    DatagramSocket* waitForNextConnection() const;

private:
    //==============================================================================
    String hostName;
    int volatile portNumber, handle;
    bool connected, allowBroadcast, allowReuse;
    IpAddress localAddress;
    void* serverAddress;

    DatagramSocket (const String& hostname, int portNumber, int handle, int localPortNumber);

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (DatagramSocket);
};


#endif   // __JUCE_SOCKET_JUCEHEADER__
