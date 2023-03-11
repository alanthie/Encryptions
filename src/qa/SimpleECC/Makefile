#--------------------------------------------
# predefine rule
#--------------------------------------------
.PHONY: clean

#--------------------------------------------
# Tool configuration
#--------------------------------------------
CC = gcc
LINKER = $(CC)
EXT = c
LIB = -lgmp
MKDIR = mkdir -p
INCLUDE = 
CFLAGS += -O2 -g
LDFLAGS = 

#--------------------------------------------
# Path configuration
#--------------------------------------------
MODULES = $(wildcard src/*.$(EXT))
SOURCEDIR = src
BINDIR = bin
TARGET = main

#--------------------------------------------
# Suffix
#--------------------------------------------
$(BINDIR)/%.o : $(SOURCEDIR)/%.$(EXT)
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDE)

# Compiling main
OBJS := ${MODULES:src/%.$(EXT)=bin/%.o}

#--------------------------------------------
# target
#--------------------------------------------
all: mkdir $(OBJS)
	$(LINKER) -o $(BINDIR)/$(TARGET) $(OBJS) $(LIB) $(LDFLAGS)

mkdir: 
	$(MKDIR) $(BINDIR)

# Run
run:
	$(BINDIR)/$(TARGET)

# Cleaning compilation
clean:
	rm -rf $(BINDIR)/*.o
	rm -rf $(BINDIR)/*~
