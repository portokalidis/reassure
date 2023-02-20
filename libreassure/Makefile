include ../config.mak
include ../makefile.common

TARGET=libreassure.a
LIBREASSURE_OBJS=libreassure.o RescuePoint.o threadstate.o utils.o
LIBREASSURE_OBJS+=writeslog.o fork.o filter.o
LIBREASSURE_HEADS=RescuePoint.hpp threadstate.hpp utils.hpp
LIBREASSURE_HEADS+=writeslog.h libreassure.hpp
LIBREASSURE_HEADS+=fork.h filter.hpp cache.h
EXT_HEADS=../include/log.hpp ../include/debug.h

CXXFLAGS+=-I../include -I$(LIBCROSSDEV_DIR)


all: $(TARGET)

.PHONY: clean


$(TARGET): $(LIBREASSURE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(LIBREASSURE_OBJS): %.o: %.cpp $(LIBREASSURE_HEADS) $(EXT_HEADS)
	$(CXX) $(CXXFLAGS) $(PIN_CXXFLAGS) -c $< 


clean:
	rm -f $(TARGET) *.o

