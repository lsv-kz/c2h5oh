CFLAGS = -Wall -O2 -g -std=c++11
#  
CC = c++ -DLINUX_
#CC = clang++  -fno-inline  -DFREEBSD_

OBJSDIR = objs
#$(shell mkdir -p $(OBJSDIR))

OBJS = $(OBJSDIR)/c2h5oh.o \
	$(OBJSDIR)/ssl.o \
	$(OBJSDIR)/cgi.o \
	$(OBJSDIR)/fcgi.o \
	$(OBJSDIR)/scgi.o \
	$(OBJSDIR)/classes.o \
	$(OBJSDIR)/create_headers.o \
	$(OBJSDIR)/config.o \
	$(OBJSDIR)/threads_manager.o \
	$(OBJSDIR)/response.o \
	$(OBJSDIR)/event_handler.o \
	$(OBJSDIR)/socket.o \
	$(OBJSDIR)/percent_coding.o \
	$(OBJSDIR)/functions.o \
	$(OBJSDIR)/log.o \
	$(OBJSDIR)/index.o \

c2h5oh: $(OBJS)
	$(CC) $(CFLAGS) -o $@  $(OBJS) -lpthread -L/usr/local/lib/ -L/usr/local/lib64/ -lssl -lcrypto

$(OBJSDIR)/c2h5oh.o: c2h5oh.cpp main.h string__.h
	$(CC) $(CFLAGS) -c c2h5oh.cpp -o $@

$(OBJSDIR)/ssl.o: ssl.cpp main.h string__.h
	$(CC) $(CFLAGS) -c ssl.cpp -o $@

$(OBJSDIR)/cgi.o: cgi.cpp main.h string__.h
	$(CC) $(CFLAGS) -c cgi.cpp -o $@

$(OBJSDIR)/fcgi.o: fcgi.cpp main.h string__.h
	$(CC) $(CFLAGS) -c fcgi.cpp -o $@

$(OBJSDIR)/scgi.o: scgi.cpp main.h string__.h
	$(CC) $(CFLAGS) -c scgi.cpp -o $@

$(OBJSDIR)/classes.o: classes.cpp main.h ranges.h string__.h
	$(CC) $(CFLAGS) -c classes.cpp -o $@

$(OBJSDIR)/create_headers.o: create_headers.cpp main.h string__.h
	$(CC) $(CFLAGS) -c create_headers.cpp -o $@

$(OBJSDIR)/config.o: config.cpp main.h string__.h
	$(CC) $(CFLAGS) -c config.cpp -o $@

$(OBJSDIR)/threads_manager.o: threads_manager.cpp main.h string__.h ranges.h
	$(CC) $(CFLAGS) -c threads_manager.cpp -o $@

$(OBJSDIR)/response.o: response.cpp main.h ranges.h string__.h
	$(CC) $(CFLAGS) -c response.cpp -o $@

$(OBJSDIR)/event_handler.o: event_handler.cpp main.h ranges.h string__.h
	$(CC) $(CFLAGS) -c event_handler.cpp -o $@

$(OBJSDIR)/socket.o: socket.cpp main.h string__.h
	$(CC) $(CFLAGS) -c socket.cpp -o $@

$(OBJSDIR)/percent_coding.o: percent_coding.cpp main.h
	$(CC) $(CFLAGS) -c percent_coding.cpp -o $@

$(OBJSDIR)/functions.o: functions.cpp main.h string__.h
	$(CC) $(CFLAGS) -c functions.cpp -o $@

$(OBJSDIR)/log.o: log.cpp main.h string__.h
	$(CC) $(CFLAGS) -c log.cpp -o $@

$(OBJSDIR)/index.o: index.cpp main.h string__.h
	$(CC) $(CFLAGS) -c index.cpp -o $@


clean:
	rm -f server
	rm -f $(OBJSDIR)/*.o
