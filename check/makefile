CFLAG = -std=c++11 -g
BIN = luhn_check luhn_code

ALL: $(BIN)

luhn_check: luhn.cpp
	g++ $^ $(CFLAG)  -o $@ -DMAIN_LUHN_CHECK

luhn_code: luhn.cpp
	g++ $^ $(CFLAG)  -o $@ -DMAIN_LUHN_CODE

.PHONY:clean
clean:
	rm -rf $(BIN)
