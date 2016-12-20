# CloudFS
CloudFS is a Windows File System Filter Driver to hook file reading and writing operations. Current version is able to handle file content transformations where file length is not supposed to change. This code is under development. Being a driver, any software issue may cause BSOD or permanent damage to the file system. If you would like to try this program, use an additional VM with Windows 7 (or newer Windows version) installed. It's a good idea to take a snapshot of the VHD.

To build this code, you will need Visual Studio 2013, Windows SDK and Windows Driver Kit.

Note: before publishing any filter drvier, you have to obtain an altitude value directly from Microsoft (to keep the target system stable). I have not requested an altitude value yet.
