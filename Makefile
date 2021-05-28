VERSION		:= 1.0
BASENAME	:= libgmalg
STATICLIB	:= $(BASENAME).a
SHAREDLIB	:= $(BASENAME).so
TARGET      := 


DIR_OBJ		= ./obj
SOURCES		:= $(wildcard *.c)
OBJS		= $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir ${SOURCES}))

export CC STRIP MAKE AR
.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o ${DIR_OBJ}/$(SHAREDLIB) $(OBJS)
	$(AR) -cr ${DIR_OBJ}/$(STATICLIB) $(OBJS)

${DIR_OBJ}/%.o:%.c
	test -d $(DIR_OBJ) || mkdir -p $(DIR_OBJ)
	$(CC) $(CFLAGS) -c  $< -o $@

clean:
	$(RM) *.so.* ${DIR_OBJ}/* ${DIR_OBJ}/$(OBJS) ${DIR_OBJ}/$(SHAREDLIB) ${DIR_OBJ}/$(STATICLIB)
