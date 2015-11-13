# Items TODO

## Project
0. Document how to use this script for application code
1. Refactor to separate config from execution
2. Determine how to unit test the code
3. Determine how to make this a pip package
4. Refactor to model an AWS role as an actual object
5. Better model who writes to config files happen. Flush/sync at close?
6. Use a pid file to prevent concurrent mods of config?
7. Move default config building out of script
8. Consider a disable ntlm fallback flag
9. Replace 'saml-i' with saml-<random> to avoid order based assumptions
10. Consider not replacing existing tokens if they are not near expiration
11. Consider a purge flag to remove previously prompted values

## Author Skill
1. Learn about Python type system and any available benefits
2. Learn about simplified config management
3. Learn about string formatting techniques in Python
4. Learn about python command line args handling
5. Can python scripts be run natively on Windows
