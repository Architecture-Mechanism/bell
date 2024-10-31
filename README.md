# bell
Bell is a comprehensive privilege escalation system designed for secure command execution with granular access controls, robust auditing, and compliance features

## Bellande Operating System Access
```
EXTENDED 5-LEVEL PERMISSION SYSTEM (77777)
========================================

BASIC PERMISSION VALUES
----------------------
Read (r)    = 4
Write (w)   = 2
Execute (x) = 1

PERMISSION NUMBER MEANINGS
------------------------
0 = --- = no access
1 = --x = execute only
2 = -w- = write only
3 = -wx = write and execute
4 = r-- = read only
5 = r-x = read and execute
6 = rw- = read and write
7 = rwx = read, write, and execute (full access)

POSITION MEANINGS (LEFT TO RIGHT)
-------------------------------
Position 1 (leftmost) = Owner/Bell
Position 2           = Root
Position 3           = Administration
Position 4           = Group
Position 5 (rightmost)= User

STANDARD PERMISSION: 77531
-------------------------
Owner (7)         = rwx = 4+2+1 = 7
Root (7)          = rwx = 4+2+1 = 7
Administration (5) = r-x = 4+0+1 = 5
Group (3)         = -wx = 0+2+1 = 3
User (1)          = --x = 0+0+1 = 1

DETAILED ACCESS LEVELS
--------------------
OWNER/BELL (Position 1)
- Value: 7 (rwx)
- Calculation: 4(read) + 2(write) + 1(execute) = 7
- Access:
  * All system files and directories
  * Core components
  * Kernel level access
  * Hardware level access
  * Can override all permissions
  * Complete system control

ROOT (Position 2)
- Value: 7 (rwx)
- Calculation: 4(read) + 2(write) + 1(execute) = 7
- Access:
  * System files
  * Configuration files
  * Installation files
  * Startup sequences
  * Cannot access core components
  * Cannot modify kernel

ADMINISTRATION (Position 3)
- Value: 5 (r-x)
- Calculation: 4(read) + 0(write) + 1(execute) = 5
- Access:
  * Read system configurations
  * Execute administrative tasks
  * Manage users
  * Cannot modify system files
  * No core component access
  * No kernel modifications

GROUP (Position 4)
- Value: 3 (-wx)
- Calculation: 0(read) + 2(write) + 1(execute) = 3
- Access:
  * Modify group files
  * Execute group programs
  * Share within group
  * No read outside group
  * No system modifications
  * Limited to group scope

USER (Position 5)
- Value: 1 (--x)
- Calculation: 0(read) + 0(write) + 1(execute) = 1
- Access:
  * Execute allowed programs
  * Access own directory
  * Use basic utilities
  * No system modifications
  * No file modifications
  * No read access outside home

COMMON PERMISSION COMBINATIONS
----------------------------
77000 - System Critical Files
Owner:  7 (rwx) = 4+2+1 : Full control
Root:   7 (rwx) = 4+2+1 : Full control
Admin:  0 (---) = 0+0+0 : No access
Group:  0 (---) = 0+0+0 : No access
User:   0 (---) = 0+0+0 : No access
Use: Core system files, kernel components

77530 - Administrative Tools
Owner:  7 (rwx) = 4+2+1 : Full control
Root:   7 (rwx) = 4+2+1 : Full control
Admin:  5 (r-x) = 4+0+1 : Read + Execute
Group:  3 (-wx) = 0+2+1 : Write + Execute
User:   0 (---) = 0+0+0 : No access
Use: System management tools, configuration files

75531 - Standard Applications
Owner:  7 (rwx) = 4+2+1 : Full control
Root:   5 (r-x) = 4+0+1 : Read + Execute
Admin:  5 (r-x) = 4+0+1 : Read + Execute
Group:  3 (-wx) = 0+2+1 : Write + Execute
User:   1 (--x) = 0+0+1 : Execute only
Use: Standard applications, user programs

PERMISSION GUIDELINES
-------------------
1. New Files/Directories
   - Start restrictive (77000 for system)
   - Add permissions as needed
   - Document changes

2. Directory Requirements
   - Need execute (x) to access
   - Need read (r) to list contents
   - Need write (w) to create/delete

3. Security Practices
   - Use minimum needed permissions
   - Regular permission checks
   - Document all changes
   - Monitor access patterns

4. Important Rules
   - Higher positions override lower
   - Cannot exceed upper level permissions
   - Execute needed for directories
   - Write permission alone is rarely used

EXAMPLES AND USE CASES
---------------------
77777 - NOT RECOMMENDED
- Gives full access to all levels
- Security risk
- Never use in production

77531 - STANDARD SECURE
- Owner: Full control
- Root: Full control
- Admin: Limited control
- Group: Write in scope
- User: Execute only

77000 - SYSTEM FILES
- Only Owner and Root access
- Maximum security
- Use for critical files

75531 - USER APPLICATIONS
- Limited Root access
- Admin can manage
- Group collaboration
- User can execute
```

## License
Bell is distributed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), see [LICENSE](https://github.com/Architecture-Mechanism/bell/blob/main/LICENSE) and [NOTICE](https://github.com/Architecture-Mechanism/bell/blob/main/LICENSE) for more information.
