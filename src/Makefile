pwd = $(shell pwd)
bc = bcprov-jdk15on-164.jar

clean:
	rm -rf shared_files *.class *.bin *.rsa

all:
	javac -cp .:$(pwd)/$(bc) *.java

RunGroupServer: all
	java -cp .:$(pwd)/$(bc) RunGroupServer

RunFileServer: all
	java -cp .:$(pwd)/$(bc) RunFileServer

ClientCLI: all
	java -cp .:$(pwd)/$(bc) ClientCLI
