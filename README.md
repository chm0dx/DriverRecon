# DriverRecon

    Enumerate drivers registered on a machine and return back useful info such as certificate subject, certificate issue date, whether IoCreateDevice or IoCreateDeviceSecure are found, and string matches which may represent SDDLs, devices, or symlinks. Designed to make your life a little easier in deciding which drivers to target for exploitation.

EX:
    Invoke-DriverRecon
    
    Invoke-DriverRecon -IgnoreSubjects "Microsoft, Intel"
