// Copyright (c) 2019 Andy Pan
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

package gnet

import (
	"net"
	"os"
	"sync"

	"github.com/panjf2000/gnet/errors"
	"github.com/panjf2000/gnet/internal/netpoll"
	"github.com/panjf2000/gnet/internal/reuseport"
	"golang.org/x/sys/unix"
)

type listener struct {
	once          sync.Once
	fd            int
	lnaddr        net.Addr
	reusePort     bool
	addr, network string
}

func (ln *listener) Dup() (int, string, error) {
	return netpoll.Dup(ln.fd)
}

func (ln *listener) normalize() (err error) {
	// XXX(zy): 下面的package为什么是从 reuseport package中引出来。

	// 在这里按照 tcp/uid/unix 进行区分socket类型
	switch ln.network {
	case "tcp", "tcp4", "tcp6":
		// 在 reuseport.TCPSocket 中，创建了tcpaddr，socket fd，
		// 然后做了bind、listen的操作。
		//
		// 监听在fd上，netaddr为lnaddr。
		ln.fd, ln.lnaddr, err = reuseport.TCPSocket(ln.network, ln.addr, ln.reusePort)
		ln.network = "tcp"
	case "udp", "udp4", "udp6":
		ln.fd, ln.lnaddr, err = reuseport.UDPSocket(ln.network, ln.addr, ln.reusePort)
		ln.network = "udp"
	case "unix":
		// TODO(zy): 后面看看unixsocket是怎么处理的。
		_ = os.RemoveAll(ln.addr)
		ln.fd, ln.lnaddr, err = reuseport.UnixSocket(ln.network, ln.addr, ln.reusePort)
	default:
		err = errors.ErrUnsupportedProtocol
	}
	return
}

func (ln *listener) close() {
	ln.once.Do(
		func() {
			if ln.fd > 0 {
				sniffErrorAndLog(os.NewSyscallError("close", unix.Close(ln.fd)))
			}
			if ln.network == "unix" {
				sniffErrorAndLog(os.RemoveAll(ln.addr))
			}
		})
}

func initListener(network, addr string, reusePort bool) (l *listener, err error) {
	// listener初始化的时候，先保存必要的配置信息。
	l = &listener{network: network, addr: addr, reusePort: reusePort}

	// 在这里进行初始化“设置”。使用前面传入的参数进行初始化设置。
	// 刚看完这个函数，发现这里面做了好多操作。。。
	// 简单来说：建立了socket连接，并且进行了监听。
	err = l.normalize()
	return
}
