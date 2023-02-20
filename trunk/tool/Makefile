include ../config.mak
include ../makefile.common

TARGET=reassure.so
REASSURE_OBJS=reassure.o watchdog.o 
REASSURE_HEADS=reassure.h 
#threadstate.hpp utils.hpp
#LIBREASSURE_HEADS+=writeslog.h libreassure.hpp
#LIBREASSURE_HEADS+=fork.h filter.hpp cache.h
EXT_HEADS=../include/log.hpp ../include/debug.h
EXT_HEADS+=../libreassure/libreassure.hpp
EXT_LIBS=../libreassure/libreassure.a

LIBS=-lrt -lreassure -lcrossdev
CXXFLAGS+=-I../include -I../libreassure -I$(LIBCROSSDEV_DIR)
LDFLAGS=-L../libreassure -L$(LIBCROSSDEV_DIR)


all: $(TARGET)

.PHONY: clean

reassure.so: $(REASSURE_OBJS) $(EXT_LIBS)
	$(CXX) $(PIN_LDFLAGS) $(LDFLAGS) -o $@ $(REASSURE_OBJS) $(LIBS) $(PIN_LIBS) 

$(REASSURE_OBJS): %.o: %.cpp $(REASSURE_HEADS) $(EXT_HEADS)
	$(CXX) $(CXXFLAGS) $(PIN_CXXFLAGS) -c $< 


clean:
	rm -f $(TARGET) *.o

