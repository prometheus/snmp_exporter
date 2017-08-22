package colour

import (
	"reflect"
	"testing"
)

func TestFormatString(t *testing.T) {
	expected := []string{
		"\033[30mblack \033[31mred \033[32mgreen \033[33myellow \033[34mblue \033[35mmagenta \033[36mcyan \033[37mwhite\033[0m",
		"\033[30m\033[40mblack \033[41mred \033[42mgreen \033[43myellow \033[44mblue \033[45mmagenta \033[46mcyan \033[47mwhite\033[0m",
		"\033[1m\033[30mblack \033[31mred \033[32mgreen \033[33myellow \033[34mblue \033[35mmagenta \033[36mcyan \033[37mwhite\033[0m",
		"\033[1m\033[30m\033[40mblack \033[41mred \033[42mgreen \033[43myellow \033[44mblue \033[45mmagenta \033[46mcyan \033[47mwhite\033[0m",
		"\033[4m\033[30mblack \033[31mred \033[32mgreen \033[33myellow \033[34mblue \033[35mmagenta \033[36mcyan \033[37mwhite\033[0m",
		"\033[4m\033[30m\033[40mblack \033[41mred \033[42mgreen \033[43myellow \033[44mblue \033[45mmagenta \033[46mcyan \033[47mwhite\033[0m",
	}
	actual := []string{
		FormatString("^0black ^1red ^2green ^3yellow ^4blue ^5magenta ^6cyan ^7white^R"),
		FormatString("^0^8black ^9red ^agreen ^byellow ^cblue ^dmagenta ^ecyan ^fwhite^R"),
		FormatString("^B^0black ^1red ^2green ^3yellow ^4blue ^5magenta ^6cyan ^7white^R"),
		FormatString("^B^0^8black ^9red ^agreen ^byellow ^cblue ^dmagenta ^ecyan ^fwhite^R"),
		FormatString("^U^0black ^1red ^2green ^3yellow ^4blue ^5magenta ^6cyan ^7white^R"),
		FormatString("^U^0^8black ^9red ^agreen ^byellow ^cblue ^dmagenta ^ecyan ^fwhite^R"),
	}
	for i := 0; i < len(actual); i++ {
		if expected[i] != actual[i] {
			t.Errorf("'%s' did not format as expected", actual[i])
		}
	}
}

func TestStripArgs(t *testing.T) {
	actual := []interface{}{1, 2, "^^^0black ^1red ^2green ^3yellow ^4blue ^5magenta ^6cyan ^7white^R", 3}
	expected := []interface{}{1, 2, "^black red green yellow blue magenta cyan white", 3}
	actual = stripArgs(actual...)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Arguments did not strip correctly")
	}
}
