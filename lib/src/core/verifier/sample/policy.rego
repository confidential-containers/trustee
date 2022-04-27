package policy

# By default, deny requests.
default allow = false

allow {
    input.cpusvn >= data.cpusvn
    input.svn >= data.svn
}