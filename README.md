UDP Multicast Heartbeat Program

To compile run ```make``` 

Running the program:

1. Basic Usage:
   ```
   ./heartbeat <user_id> [options]
   ```

2. Options:
   - `-m <multicast_ip>` or `--multicast-ip=<multicast_ip>`: Override default multicast IP (239.0.0.1)
   - `-p <port>` or `--port=<port>`: Override default port (12345)
   - `-c <initial_interval>`: Start as controller with specified heartbeat interval (0-30)

3. Examples:
   - Run as a client:
     ```
     ./heartbeat client1
     ```
   - Run as a controller with 5-second heartbeat interval:
     ```
     ./heartbeat controller1 -c 5
     ```
   - Run with custom multicast IP and port:
     ```
     ./heartbeat client2 -m 239.0.0.2 -p 12346
     ```

4. Controller Commands:
   - Enter a number (0-30) to change the heartbeat interval
   - Type `exit` to gracefully shut down
   - Type `abort` to force shutdown

5. Client Behavior:
   - Automatically sends heartbeats at the interval set by the controller
   - Can become controller if current controller goes down. Must specify a number between (0-30) to accept
   - Logs all activities to `heartbeat_app_<user_id>.log`

6. Notes:
   - The program uses UDP multicast for communication
   - Multiple clients can run simultaneously
   - Only one controller can be active at a time
   - Log files are created in the current directory
