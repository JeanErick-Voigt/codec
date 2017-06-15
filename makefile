


all: encode decode

encode: encode.c
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c -lm

decode: decode.c
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c -lm

debug:
	gcc -g -o decode decode.c -lm
	gcc -g -o encode encode.c -lm

clean:
	rm -f encode 
	rm -f decode


