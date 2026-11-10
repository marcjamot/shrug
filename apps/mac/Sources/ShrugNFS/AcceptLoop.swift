import Darwin
import Foundation

/// Accepts connections on a listening socket, on its own thread, until stopped.
///
/// Only that thread closes the socket, and only after it has stopped accepting. Closing it from
/// elsewhere would let the system hand the same descriptor number to something else while the
/// thread is about to accept on it. (On macOS, shutdown() doesn't wake a blocked accept(), so
/// the thread waits on the socket and on a pipe that `stop` writes to.)
public final class AcceptLoop: @unchecked Sendable {
    private let fd: Int32
    private let wakeRead: Int32
    private let wakeWrite: Int32
    private let finished = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var stopped = false

    /// Takes over `fd`, which must be listening. `onAccept` runs on the loop's thread with
    /// each new connection, which it then owns.
    public init(listening fd: Int32, name: String, onAccept: @escaping (Int32) -> Void) throws {
        var ends: [Int32] = [-1, -1]
        guard pipe(&ends) == 0 else {
            close(fd)
            throw NFSServerError("pipe() failed: \(String(cString: strerror(errno)))")
        }
        self.fd = fd
        wakeRead = ends[0]
        wakeWrite = ends[1]
        _ = fcntl(wakeWrite, F_SETNOSIGPIPE, 1)
        // Never block in accept() if a waiting connection went away after poll() saw it.
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let t = Thread { [self] in run(onAccept) }
        t.name = name
        t.start()
    }

    private func run(_ onAccept: (Int32) -> Void) {
        defer {
            close(fd)
            close(wakeRead)
            finished.signal()
        }
        while true {
            var fds = [pollfd(fd: fd, events: Int16(POLLIN), revents: 0),
                       pollfd(fd: wakeRead, events: Int16(POLLIN), revents: 0)]
            if poll(&fds, 2, -1) < 0 {
                if errno == EINTR { continue }
                return
            }
            if fds[1].revents != 0 { return }
            if fds[0].revents & Int16(POLLIN) != 0 {
                let client = accept(fd, nil, nil)
                guard client >= 0 else { continue }
                // Accepted sockets inherit O_NONBLOCK on macOS; connections are served blocking.
                _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK)
                onAccept(client)
            } else if fds[0].revents != 0 {
                return // the listening socket broke
            }
        }
    }

    /// Stops accepting and returns once the socket is closed.
    public func stop() {
        lock.lock()
        let first = !stopped
        stopped = true
        lock.unlock()
        guard first else { return }
        var one: UInt8 = 1
        _ = write(wakeWrite, &one, 1)
        _ = finished.wait(timeout: .now() + 5)
        close(wakeWrite)
    }
}
