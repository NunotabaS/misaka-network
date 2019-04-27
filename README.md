# misaka-network
A small Python application that uses public services to synchronize files

## Concept
This script allows the user to set up configuration synchronization on a remote
server that has public profiles that may not be fully controlled by the user.

**Example**: Suppose MyService.com allows openly registering new users, who can 
then upload custom data accessible publicly at `MyService.com/{username}/stuff`.

However, user accounts may be closed at the discretion of MyService.com. Thus to
provide a long term synchronization channel, one can imagine that the client 
can check `MyService.com/user1/stuff`, `MyService.com/user2/stuff`... until 
the client finds a (signed and authorized) blob that is acceptable. 

This application implements a generalized policy for generating id streams and
checking them for data, effectively allowing the client to continue 
synchronization even when specific accounts may be shut down.
