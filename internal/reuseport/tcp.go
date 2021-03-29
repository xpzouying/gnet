// Copyright (c) 2020 Andy Pan
// Copyright (c) 2017 Max Riveiro
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// +build linux freebsd dragonfly darwin

package reuseport

import (
	"net"
	"os"

	"github.com/panjf2000/gnet/errors"
	"golang.org/x/sys/unix"
)

var listenerBacklogMaxSize = maxListenerBacklog()

// NOTE(zy): 我喜欢这种函数定义形式。返回值比较多的时候，将所有的变量都定义在返回值上，这样至少可以有2个目的：
// 1. 不需要在函数中，定义这些返回值对象，特别是包含一个比较大结构体的对象；
// 2. 可以省去函数的返回值注释，用变量名直接说明。
func getTCPSockaddr(proto, addr string) (sa unix.Sockaddr, family int, tcpAddr *net.TCPAddr, err error) {
	var tcpVersion string

	// 需要先创建Go里面的http地址。
	// 通过 proto + addr 创建 tcpAddr结构体。
	// 然后通过tcpAddr创建socket file descriptor。
	tcpAddr, err = net.ResolveTCPAddr(proto, addr)
	if err != nil {
		return
	}

	// 真的细节。在这里还特意判断一下 tcp的版本。因为在函数传入的proto若为空字符串的话，
	// 这里也是为 tcp4。
	tcpVersion, err = determineTCPProto(proto, tcpAddr)
	if err != nil {
		return
	}

	switch tcpVersion {
	case "tcp":
		// 创建 tcp4的socket。socket fd包含：socket = ip+port
		sa, family = &unix.SockaddrInet4{Port: tcpAddr.Port}, unix.AF_INET
	case "tcp4":
		sa4 := &unix.SockaddrInet4{Port: tcpAddr.Port}

		if tcpAddr.IP != nil {
			if len(tcpAddr.IP) == 16 {
				copy(sa4.Addr[:], tcpAddr.IP[12:16]) // copy last 4 bytes of slice to array
			} else {
				copy(sa4.Addr[:], tcpAddr.IP) // copy all bytes of slice to array
			}
		}

		sa, family = sa4, unix.AF_INET
	case "tcp6":
		// tcp6 - 暂时忽略。
		sa6 := &unix.SockaddrInet6{Port: tcpAddr.Port}

		if tcpAddr.IP != nil {
			copy(sa6.Addr[:], tcpAddr.IP) // copy all bytes of slice to array
		}

		if tcpAddr.Zone != "" {
			var iface *net.Interface
			iface, err = net.InterfaceByName(tcpAddr.Zone)
			if err != nil {
				return
			}

			sa6.ZoneId = uint32(iface.Index)
		}

		sa, family = sa6, unix.AF_INET6
	default:
		err = errors.ErrUnsupportedProtocol
	}

	return
}

func determineTCPProto(proto string, addr *net.TCPAddr) (string, error) {
	// If the protocol is set to "tcp", we try to determine the actual protocol
	// version from the size of the resolved IP address. Otherwise, we simple use
	// the protcol given to us by the caller.

	if addr.IP.To4() != nil {
		return "tcp4", nil
	}

	if addr.IP.To16() != nil {
		return "tcp6", nil
	}

	// 现在的switch版本已经可以不用default。
	// 如果是channel呢？应该还是要的吧。
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return proto, nil
	}

	return "", errors.ErrUnsupportedTCPProtocol
}

// tcpReusablePort creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
// Argument `reusePort` indicates whether the SO_REUSEPORT flag will be assigned.
//
// 总的流程，简单的来说：
// 1. 根据请求的参数，创建出tcpAddr；
// 2. 创建socket fd，然后配置该socket fd；
// 3. bind、listen，将socket fd关联到tcpAddr。
func tcpReusablePort(proto, addr string, reusePort bool) (fd int, netAddr net.Addr, err error) {
	var (
		family   int
		sockaddr unix.Sockaddr
	)

	// 创建socket对象结构体
	if sockaddr, family, netAddr, err = getTCPSockaddr(proto, addr); err != nil {
		return
	}

	// 创建一个socket的fd。
	// family - unix.AF_INET
	// socket type - unix.SOCK_STREAM
	// proto - unix.IPPROTO_TCP
	if fd, err = sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP); err != nil {
		err = os.NewSyscallError("socket", err)
		return
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()

	// 调用syscall先创建一个socket fd。创建好了后，对该socket fd进行各种配置。
	if err = os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)); err != nil {
		return
	}

	// 如果是需要端口复用的话，则设置 unix.SO_REUSEPORT。
	// unix.SOL_SOCKET - 表示 level。具体参考：https://stackoverflow.com/questions/21515946/what-is-sol-socket-used-for。
	// 如果要设置 socket自身的参数，比如 unix.SO_REUSEPORT，则需要指定level为 unix.SOL_SOCKET。
	if reusePort {
		if err = os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)); err != nil {
			return
		}
	}

	// bind
	if err = os.NewSyscallError("bind", unix.Bind(fd, sockaddr)); err != nil {
		return
	}

	// Set backlog size to the maximum.
	err = os.NewSyscallError("listen", unix.Listen(fd, listenerBacklogMaxSize))

	return
}

// --- zy笔记 ---
// socket连接的过程在这里写的很清楚。如果要创建一个socket server的话，则需要：
//
// 1. 准备好一个sockaddr地址；
// 2. [syscall] 创建一个socket地址，并且设置socket参数；AF_INET, SOCK_STREAM, IPPROTO_TCP, SO_REUSEADDR, OS_REUSEADDR；
// 3. [syscall] bind - 将sockaddr地址和socket fd进行绑定关联；
// 4. [syscall] listen - 进行监听；
