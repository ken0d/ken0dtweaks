REM crédit : github.com/Batlez/Batlez-Tweaks
REM /// Quelques optimisation bcdedit ///
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue disabledynamictick
bcdedit /set useplatformtick Yes
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set nx AlwaysOff
bcdedit /set bootmenupolicy legacy
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set linearaddress57 OptOut
bcdedit /set firstmegabytepolicy UseAll 
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0 
bcdedit /set isolatedcontext No