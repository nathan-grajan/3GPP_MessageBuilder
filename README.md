# 3GPP_MessageBuilder
# Both files require the pycrate library
MACHeaderParser is a file that takes an input of a hexadecimal formatted string that has a 3GPP MAC header and decodes it and converts it into JSON format. It decodes the MAC header and the upper layer protocol messages and figures out the type of message that is given insisde the hex string. It then prompts for a parameter to search for and prints everything inside it. 

AsnBuilder is a program that constructs an RRC message based off the name of the message given by the user.
