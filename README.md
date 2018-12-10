Key commands

```
shh init			# initialize project or add self to existing project
shh get $secret_name		# get secret or secrets
shh set $secret_name $value	# set value
shh del $secret_name		# delete the secret
shh allow $user $secret		# allow a user access to a secret
shh deny $user $secret		# deny a user access to a secret
shh show $user			# show user's allowed and denied keys. default self
shh rotate			# rotate your key
```

Example usage:

```
# Create secret file and keys.
shh init
> creating new .shh
>
> your username (usually email): alice@example.com
> password for your secrets key:
>
> generated ~/.config/shh/config
> generated ~/.config/shh/id_rsa
> generated ~/.config/shh/id_rsa.pub
> created .shh
>
> be sure to back up ~/.config/shh/id_rsa and remember your password, or you
> may lose access to your secrets!

# Add user to an existing project (on a different computer than above)
shh init
> adding user to existing .shh
>
> your username (usually email): bob@example.com
> password for your secrets key:
>
> generated ~/.config/shh/config
> generated ~/.config/shh/id_rsa
> generated ~/.config/shh/id_rsa.pub
> added bob@example.com to .ssh
>
> be sure to back up ~/.config/shh/id_rsa and remember your password, or you
> may lose access to your secrets!

# Create a secret named "database_url"
shh create secret database_url "127.0.0.1:3304"

# An alternative syntax to create a secret
echo $DB_URL | shh create secret database_url

# You can also namespace the secrets like a filesystem. There's no built-in
# support for this, but it makes it easy to support different projects/repos
# within a single project.
shh create secret staging/database_url "127.0.0.1:3304"

# Allow a user to access a secret
shh allow bob@example.com database_url

# Deny a user from accessing a secret
shh deny bob@example.com database_url

# Deny a user from accessing all secrets
ssh deny bob@example.com *

# Show your accessible keys and meta info
shh show

# Show Bob's keys and meta info
shh show user bob@example.com

# Show all user keys and meta info
shh show user *

# In case of stolen key, you can regenerate/rotate your key
shh rotate
> old password:
> new password:
>
> generated ~/.config/shh/id_rsa
> generated ~/.config/shh/id_rsa.pub
>
> be sure to back up ~/.config/shh/id_rsa and remember your password, or you
> may lose access to your secrets!

# Pass staging secrets into server on boot
shh show secret staging/* | my_server

# Pass staging secrets to server.env on deploy
shh show secret staging/* | ssh alice@server "cat > server.env"
```
