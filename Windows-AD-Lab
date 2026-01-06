# Active Directory Home Lab Project

## Overview

I built a home lab with Active Directory to learn Windows Server administration and practice IT support skills. This project simulates a small business network with a domain controller and client computers.

## What I Built

- 1 Windows Server 2019 (Domain Controller)
- 2 Windows 10 computers (Client machines)
- Active Directory domain with users and groups
- Group policies to control user settings
- DHCP for automatic IP addresses

## Lab Setup

### Step 1: Install Proxmox

I downloaded VirtualBox from virtualbox.org and installed it on my computer. This lets me run multiple virtual machines.

### Step 2: Create the Domain Controller VM

**VM Settings:**
- Name: DC01
- OS: Windows Server 2019
- RAM: 4 GB
- Hard Drive: 60 GB
- Network: Internal Network

I installed Windows Server 2019 and set up a static IP address: 10.0.2.10

<img width="986" height="682" alt="image" src="https://github.com/user-attachments/assets/e9ba8993-ec11-419f-b816-3bd813f883bd" />


### Step 3: Install Active Directory

I used Server Manager to install Active Directory Domain Services:

1. Opened Server Manager
2. Clicked "Add Roles and Features"
3. Selected "Active Directory Domain Services"
4. After installation, promoted the server to Domain Controller
5. Created a new domain called "homelab.local"
6. Server automatically restarted

Now I have a working domain controller!

### Step 4: Set Up DHCP

I added the DHCP role so client computers could get IP addresses automatically:

1. Server Manager → Add Roles → DHCP Server
2. Created a scope: 10.0.2.100 - 10.0.2.200
3. Set DNS server to: 10.0.2.10 (the domain controller)

4. <img width="558" height="417" alt="image" src="https://github.com/user-attachments/assets/fa2aa006-f3cb-4739-a990-93552239a924" />


### Step 5: Create Organizational Units

I organized Active Directory with folders (Organizational Units):

```
homelab.local
├── IT Department
├── HR Department
├── Admin Users
└── Workstations
```

This keeps everything organized, just like folders on a computer.

### Step 6: Create User Accounts

I created test users for different departments:

**IT Department:**
- Username: john.smith
- Name: John Smith
- Password: TempPass123!

**HR Department:**
- Username: mary.jones
- Name: Mary Jones
- Password: TempPass123!

**Admin Account:**
- Username: admin.user
- Name: IT Admin
- Password: AdminPass123!

I set all accounts to "User must change password at next logon" for security.

### Step 7: Create Security Groups

I made groups to manage permissions easier:

- **IT_Team** - For IT department staff
- **HR_Team** - For HR department staff
- **Domain_Admins** - For administrators

Then I added users to their groups:
- john.smith → IT_Team
- mary.jones → HR_Team
- admin.user → Domain_Admins

<img width="1087" height="630" alt="image" src="https://github.com/user-attachments/assets/5a377982-c459-412b-b1d4-a8a1bcccbe46" />


### Step 8: Set Up Windows 10 Client Computers

I created two Windows 10 VMs:

<img width="1205" height="730" alt="image" src="https://github.com/user-attachments/assets/a1f4b5c6-32e9-4e14-8fc3-e5ea681a04c3" />


**VM Settings:**
- Names: PC01 and PC02
- OS: Windows 10 Pro (needed for domain join)
- RAM: 8 GB each
- Hard Drive: 50 GB each
- Network: Same internal network as DC01

### Step 9: Join Computers to Domain

On each Windows 10 VM:

1. Went to Settings → System → About
2. Clicked "Rename this PC (advanced)"
3. Clicked "Change" button
4. Selected "Domain" and typed: homelab.local
5. Entered domain admin username and password
6. Computer restarted
<img width="1572" height="748" alt="image" src="https://github.com/user-attachments/assets/db5b9d8a-4627-4663-81d2-a6bf98146326" />


Success! The computers are now part of the homelab.local domain.

### Step 10: Test Domain Login

I logged into PC01 using domain credentials:

1. At login screen, clicked "Other user"
2. Typed: homelab\john.smith
3. Entered password: TempPass123!
4. Windows prompted me to change password (as configured)
5. Set new password: NewPass123!
6. Successfully logged in!

<img width="1193" height="745" alt="image" src="https://github.com/user-attachments/assets/a996d4c3-a58c-411f-b098-c7f34cb1b1c5" />

The user profile was created automatically. Everything worked!

## Group Policies I Created

### Policy 1: Disable Control Panel

**Purpose:** Prevent regular users from changing system settings

**Steps:**
1. Opened Group Policy Management
2. Created new GPO: "Disable Control Panel"
3. Linked to "HR Department" OU
4. Edited policy:
   - User Configuration → Administrative Templates → Control Panel
   - Enabled "Prohibit access to Control Panel and PC settings"
5. On PC01, ran `gpupdate /force`

<img width="1391" height="745" alt="image" src="https://github.com/user-attachments/assets/77606756-420e-4863-b60a-998d19caba96" />
<img width="1211" height="753" alt="image" src="https://github.com/user-attachments/assets/5a489a65-d25f-44b5-9a8c-eca09068ea3c" />


**Result:** Mary Jones (HR user) cannot open Control Panel anymore. Perfect for restricting non-technical users!

### Policy 2: Desktop Wallpaper

**Purpose:** Set company wallpaper for all users

**Steps:**
1. Created new GPO: "Company Wallpaper"
2. Linked to entire domain
3. Configured:
   - User Configuration → Administrative Templates → Desktop → Desktop
   - Set "Desktop Wallpaper" to company image path
4. Ran `gpupdate /force` on client computers
<img width="1581" height="750" alt="image" src="https://github.com/user-attachments/assets/f7fb5e72-e054-4e21-867b-5c97ef946b16" />
<img width="1572" height="751" alt="image" src="https://github.com/user-attachments/assets/03a0fb66-611d-479e-a28e-fbda1ddd112a" />

**Result:** All users see the company wallpaper when they log in.

### Policy 3: Password Policy

**Purpose:** Enforce strong passwords

**Steps:**
1. Created new GPO: "Password Requirements"
2. Linked to domain
3. Settings:
   - Minimum password length: 8 characters
   - Password must meet complexity requirements: Enabled
   - Maximum password age: 90 days
<img width="1200" height="745" alt="image" src="https://github.com/user-attachments/assets/019b3da5-d480-4610-92df-4e0c336b8666" />

**Result:** Users must create strong passwords and change them every 90 days.

### Policy 4: Lock Screen After Inactivity

**Purpose:** Automatically lock computers after 10 minutes

**Steps:**
1. Created GPO: "Auto Lock Screen"
2. Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
3. Enabled "Interactive logon: Machine inactivity limit" → 600 seconds

**Result:** Computers lock automatically if no one is using them. Good for security!
<img width="1199" height="751" alt="image" src="https://github.com/user-attachments/assets/e2988a88-ea10-498a-a077-4b4f2e735d8f" />

## File Permissions Setup

### Shared Folder with Different Access Levels

I created a shared folder on DC01 to practice permissions:

**Folder Structure:**
```
C:\SharedFiles
├── IT_Only (IT Team only)
├── HR_Only (HR Team only)
└── Everyone (All users)
```

**IT_Only Folder Permissions:**
- IT_Team: Full Control
- HR_Team: No access
- Everyone: No access

**HR_Only Folder Permissions:**
- HR_Team: Read & Write
- IT_Team: Read only (for support)
- Everyone: No access

**Everyone Folder Permissions:**
- Domain Users: Read & Write
- Everyone: Read only

**How I Set This Up:**
1. Right-clicked folder → Properties → Sharing → Advanced Sharing
2. Shared the folder
3. Clicked "Permissions" → Removed "Everyone"
4. Added specific groups (IT_Team, HR_Team, etc.)
5. Set NTFS permissions under "Security" tab
6. Made sure NTFS permissions matched share permissions
<img width="1378" height="747" alt="image" src="https://github.com/user-attachments/assets/b98866d4-62be-4139-a28a-7f9c76504f57" />

**Testing:**
- Logged in as john.smith (IT) - Could access IT_Only folder ✓
- Logged in as mary.jones (HR) - Could NOT access IT_Only folder ✓
- Both could access Everyone folder ✓
<img width="1201" height="747" alt="image" src="https://github.com/user-attachments/assets/4e56666b-12cd-46cf-972a-219e38c677d3" />

## Testing Common IT Support Scenarios

### Scenario 1: User Forgot Password

**Problem:** Mary Jones forgot her password and can't log in.

**Solution Steps:**
1. Logged into DC01 as administrator
2. Opened "Active Directory Users and Computers"
3. Found mary.jones in HR Department OU
4. Right-clicked → "Reset Password"
5. Entered new temporary password: TempHR123!
6. Checked "User must change password at next logon"
7. Told user the temporary password
8. User logged in and was forced to create new password

**Time to resolve:** 2 minutes
<img width="1199" height="747" alt="image" src="https://github.com/user-attachments/assets/9ff48dca-b62e-4596-a851-cffa7632ebc0" />

**Skills demonstrated:** Password reset, user support, security best practices

### Scenario 2: User Account Locked Out

**Problem:** John Smith entered wrong password 5 times. Account locked.

**Solution Steps:**
1. Opened Active Directory Users and Computers
2. Found john.smith
3. Right-clicked → Properties → Account tab
4. Checked "Unlock account" checkbox
5. Clicked OK
6. User could log in immediately

**Alternative method using PowerShell:**
```powershell
Unlock-ADAccount -Identity john.smith
```
<img width="1200" height="744" alt="image" src="https://github.com/user-attachments/assets/bfadf94d-c6c9-49b3-a5bf-2da3047f1989" />

**Time to resolve:** 1 minute

### Scenario 3: New Employee Needs Account

**Problem:** New HR employee "Sarah Johnson" needs domain account.

**Solution Steps:**
1. Opened Active Directory Users and Computers
2. Right-clicked "HR Department" OU → New → User
3. Filled in information:
   - First name: Sarah
   - Last name: Johnson
   - User logon name: sarah.johnson
4. Set temporary password: TempHR456!
5. Checked "User must change password at next logon"
6. Clicked Finish
7. Added sarah.johnson to HR_Team group
8. Verified permissions by logging in as Sarah
<img width="1194" height="753" alt="image" src="https://github.com/user-attachments/assets/f1fea798-bed9-4489-b7c0-75c07164af01" />

**Time to complete:** 5 minutes

### Scenario 4: User Can't Access Shared Folder

**Problem:** Mary Jones says "Access Denied" when opening IT_Only folder.

**Diagnosis:**
1. Checked what groups Mary is in: `HR_Team`
2. Checked IT_Only folder permissions: Only `IT_Team` has access
3. This is correct! HR shouldn't access IT files
<img width="1195" height="748" alt="image" src="https://github.com/user-attachments/assets/d6193e89-0441-41c7-9d5a-710933417b31" />

**Resolution:**
Explained to user that this folder is restricted to IT department only. Not a problem - security working as designed!

If she actually NEEDED access, I would:
1. Ask IT manager for approval
2. Add mary.jones to IT_Team group OR
3. Add HR_Team to folder permissions with appropriate access level
<img width="1191" height="749" alt="image" src="https://github.com/user-attachments/assets/0658e93f-147b-41f9-9439-8f87af0e0545" />

**Time to resolve:** 3 minutes

**Skills demonstrated:** Troubleshooting, checking permissions, security awareness

### Scenario 5: User Can't Log Into Domain

**Problem:** PC02 says "The trust relationship between this workstation and the primary domain failed."

**Cause:** Computer account password expired or corrupt.

**Solution Steps:**
1. Logged into PC02 with local administrator account
2. Removed computer from domain (joined workgroup temporarily)
3. Restarted computer
4. Rejoined computer to homelab.local domain
5. Restarted again
6. User could log in successfully

**Alternative PowerShell fix (on DC01):**
```powershell
Reset-ComputerMachinePassword -Server DC01 -Credential HOMELAB\Administrator
```

**Time to resolve:** 10 minutes

### Scenario 6: User Needs Access to New Shared Folder

**Problem:** Create new shared folder for Finance department.

**Solution Steps:**
1. Created folder: C:\SharedFiles\Finance_Only
2. Shared the folder with share permissions:
   - Finance_Team: Full Control
3. Set NTFS security permissions:
   - Finance_Team: Modify
   - Domain Admins: Full Control
   - Removed all other permissions
4. Created shortcut in user's Group Policy mapped drives
5. Tested access with Finance user account
<img width="1191" height="750" alt="image" src="https://github.com/user-attachments/assets/57fb2e35-4891-4a9a-a3c6-ae5c2ae5a276" />
<img width="1194" height="749" alt="image" src="https://github.com/user-attachments/assets/002dad18-11f1-490a-94fb-0e75824ddb60" />

**Time to complete:** 8 minutes

### Scenario 7: Apply Group Policy Not Working

**Problem:** Desktop wallpaper policy not applying to PC01.

**Troubleshooting Steps:**
1. On PC01, opened Command Prompt as administrator
2. Ran: `gpupdate /force` to force policy refresh
3. Ran: `gpresult /r` to see applied policies
4. Checked if policy was actually linked to correct OU
5. Verified computer was in correct OU in Active Directory
6. Restarted PC01

**Result:** Policy applied successfully after restart!

**Lessons learned:** 
- Group policies need `gpupdate` or restart to apply
- Always check policy is linked to correct OU
- Use `gpresult` to troubleshoot policy issues

## Key Skills Demonstrated

**Windows Server Administration:**
- Active Directory installation and configuration
- Domain controller setup
- DNS and DHCP configuration
- User and group management

**Group Policy Management:**
- Creating and linking GPOs
- User restrictions and security policies
- Desktop management policies
- Troubleshooting policy application

**Security & Permissions:**
- NTFS permissions configuration
- Share permissions setup
- Security group management
- Principle of least privilege

**IT Support Skills:**
- Password resets
- Account unlocking
- New user creation
- Access troubleshooting
- Domain join issues
- Group policy troubleshooting

**PowerShell:**
- Basic AD commands
- User management automation
- Troubleshooting commands

## Challenges I Overcame

**Challenge 1:** VM wouldn't connect to domain
- **Solution:** Checked DNS settings - client was using wrong DNS server. Changed to point to DC (10.0.2.10)
<img width="1526" height="752" alt="image" src="https://github.com/user-attachments/assets/7ec6c5eb-9af1-461d-b321-43120b815beb" />

**Challenge 2:** Group Policy not applying
- **Solution:** Ran `gpupdate /force` and restarted computer. Learned policies don't apply instantly.

**Challenge 3:** NTFS permissions weren't changing
- **Solution:** NTFS permissions were allowing inheritance from parent. Learned that this setting is configured separately.
<img width="1202" height="755" alt="image" src="https://github.com/user-attachments/assets/ec6ad070-1ce5-448b-af12-f7a3dbb13553" />

**Challenge 4:** Forgot DSRM password for DC
- **Solution:** Documented all passwords in secure location. Learned importance of password management.

## What I Learned

1. **Active Directory is the backbone** of Windows networks - everything connects to it
2. **Group Policy is powerful** - you can control almost anything on user computers
3. **Permissions are tricky** - both share AND NTFS permissions matter
4. **Documentation is critical** - I documented every step and it saved me many times
5. **Testing is important** - Always test from a user's perspective
6. **Troubleshooting methodology** - Check basics first (DNS, connectivity), then dig deeper

## Future Improvements

- Add file server with home drives for each user
- Set up certificate services for SSL certificates
- Create automated backup solution
- Add Linux client and integrate with Active Directory
- Implement Remote Desktop Services
- Set up VPN access for remote users
- Create disaster recovery plan and test it

## Resources Used

- Microsoft Documentation
- KevTech's YouTube Videos
- Claude
- My own trial and error!


## Contact

Questions about this project? Feel free to reach out!

- Email: keikoyoter@gmail.com
- LinkedIn: [your-linkedin-profile](https://www.linkedin.com/in/koyo-keiter-20962b37a/)
- GitHub: Koyo-dotcom

---

**Project Status:** Complete ✓  
**Date Completed:** November 2024  
**Time Invested:** ~10 hours over 2 weeks
