# AutoShell

[![IMG-1321](https://i.ibb.co/hsZhttV/IMG-1321.png)](https://ibb.co/fMnBPPH) [![IMG-1323](https://i.ibb.co/mSvq0xK/IMG-1323.png)](https://ibb.co/258tSbr)


This code is a web scanner tool designed to find vulnerabilities and file upload points on a website. It uses various techniques to bypass security measures and upload files in a hidden manner. In the following, the technical details of the code and the techniques used will be explained.

Different parts of the code:

1. Initial settings:
In this section, the necessary variables for running the code are defined. Some of these variables include:
	* `logger`: A logging class object used to keep track of events and errors in the code.
	* `RANDOM_COMMANDS`: A list of random commands that are used to execute the code on the server.
	* `IMAGE_FILE`: A string that represents the name of the image file used to hide the code in it.
2. Generating random code:
The `generate_random_shell` and `random_shell_name` functions are defined in this section. The `generate_random_shell` function generates a random code using one of the random commands from the `RANDOM_COMMANDS` list. The `random_shell_name` function generates a random name for the code file.
3. Finding the upload point:
The `find_upload_point` function is used to find the file upload point on a website. This function uses the `requests` and `BeautifulSoup` libraries to retrieve the main page of the website and then finds the forms that have a file upload field. If no form is found, this function finds a list of website links using the `ContentDiscovery` class and then finds the forms that have a file upload field for each link.
4. Uploading the file:
The `upload_file` function is used to upload the file to an upload point. This function uses various techniques to bypass security measures and upload the file in a hidden manner. Some of these techniques include:
	* Changing the file extension: This technique uses a unknown file extension to bypass website security.
	* Adding null byte character: This technique adds a null byte character to the end of the file name to bypass website security.
	* Adding double extension: This technique adds a double extension to the file name to bypass website security.
	* Increasing file size: This technique increases the file size to bypass website security.
	* Adding code to an image: This technique adds the code to an image file to hide the code and bypass website security.
	* Using base64 encoding: This technique encodes the file using base64 encoding to hide the code and bypass website security.
	* Using gzinflate: This technique compresses the file using gzinflate to hide the code and bypass website security.
	* Using eval: This technique uses the JavaScript eval function to execute the code and bypass website security.
	* Using data URI: This technique uses data URI to hide the code and bypass website security.
	* Using custom extension: This technique uses a custom file extension for the file to bypass website security.
	* Using polyglot file: This technique creates a polyglot file to hide the code and bypass website security.
	* Using steganography: This technique hides the code in an image using steganography to bypass website security.
5. Testing and execution:
The `try_upload_methods` function is used to test and execute the `find_upload_point` and `upload_file` functions. This function tries to find the file upload point and then uploads the file in a hidden manner for each website entered by the user. If the upload is successful, the address of the uploaded file on the website is printed.

Finally, the `main` function is used to run the code and get user inputs. This function generates a random name for the file and then tries to upload the file to the website using the `try_upload_methods` function.

This code is a powerful tool for finding vulnerabilities and file upload points on a website. Using various techniques to bypass website security and upload files in a hidden manner, this tool can be very useful for testing website security. It should be noted that the use of this tool should be done responsibly and with the necessary permissions.
