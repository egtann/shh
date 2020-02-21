# shh

shh manages secrets for projects and small teams. Secrets are encrypted and
safe to commit to version control software like git.

Unlike Hashicorp Vault, shh requires no infrastructure. There's no server to
manage and secure -- just a single file.

## Getting started

First, generate encryption keys:

```
shh gen-keys
```

You'll be asked to choose a username and set a password. Be sure to remember
your password.

`gen-keys` places keys in `~/.config/shh`. Back up your id_rsa private key; if
lost there's no way to recover it!

Next, initialize a new project:

```
shh init
```

This creates a `.shh` file in your current working directory which will be used
to store your secrets. Your public key was automatically added to the `.shh`
file, so you can now add secrets, like so:

```
shh set staging/env "$(cat staging.env)"
```

Where `staging/env` is the name of the secret and the content of the file
`staging.env` is the secret itself.

You can retrieve that secret with `get` like this:

```
shh get staging/env
```

You'll have to enter your password to retrieve the secret.

> **NOTE:** There's no concept in shh of directories or `/`, but it's useful to
> namespace your secrets for glob matches as described later.
>
> Also note that secrets belong to a global namespace. If Bob creates secret
> "A", but Alice doesn't have access, Alice trying to create a secret named "A"
> will result in an error. The same name resolves to the same secret for every
> user in the project, regardless of whether or not that user has access.

If you need to edit your secret, `shh edit staging/env` can do it. That uses
your `$EDITOR` of choice. Note that `$EDITOR` should be an absolute path. Save
and quit to re-encrypt the updated version without ever saving an unencrypted
version to disk.

You can rename a secret with `rename` like this:

```
shh rename old-name new-name
```

If you want to start a new secret using another secret as a starting point and
maintain all teammates' access:

```
shh copy old-name new-name
```

This may be useful when you're setting up a new environment, such as:

```
shh copy production/env staging/env
```

## Team management

You can grant and revoke access to secrets among teammates at any time. First
ensure they're added to the project, which will require their public key
generated via `gen-key`:

```
shh add-user alice@example.com pubkey.pem
```

Now they're added to the project, but they don't have access to any keys:

```
shh allow alice@example.com staging/env
```

You can only allow access to keys which you, yourself, have access to.

Save time by using glob matches like this to grant access to an entire
namespace:

```
shh allow alice@example.com staging/*
```

You can revoke access to individual or globbed keys, like this:

```
shh deny alice@example.com staging/env
```

Or you can remove a user from a project entirely, which will remove all of
their secrets and delete their public key from `.shh`:

```
shh rm-user alice@example.com
```

## Advanced usage

### Serve and login

If you're using shh, you'll probably need to retrieve secrets during deploys
and other scripts. That's why there's `shh serve`, which saves your password in
memory for 1 hour.

You can set the port in your `~/.config/shh/config` file like this:

```
username=bob@example.com
port=4850
```

Then run `shh serve` and from another terminal run `shh login` to set your
password in memory. Now you can run `get` or `allow` without needing to enter
your password each time -- especially useful during deploy scripts.

### Rotate

If your private key is compromised or you need to change your password, you can
easily change your keys:

```
shh rotate
```

This will ask for a new password, generate new keys and re-encrypt all secrets
using that new password.

### Using the command line

See the difference in secrets granted between two users:

```
diff -y <(shh show alice@example.com) <(shh show bob@example.com)
```

Edit all files containing a regular expression:

```
shh search "\d{8,}" | xargs -I % -o shh edit %
```

Count the number of secrets to which a user has access:

```
shh show bob@example.com | wc -l
```

See the changes in an shh file across commits:

```
vimdiff \
	<(shh -f <(git show commit_1:.shh) get my_secret) \
	<(shh -f <(git show commit_2:.shh) get my_secret)
```


## Key commands

```
shh init			# initialize project, creating .shh file
shh gen-keys			# generate keys
shh get $secret_name		# get secret or secrets
shh set $secret_name $value	# set value
shh del $secret_name		# delete secret
shh allow $user $secret		# allow access to secret
shh deny $user $secret		# deny access to secret
shh add-user [$user $pubkey]	# add user to project, default self
shh rm-user $user		# remove user from project
shh show [$user]		# show user's allowed and denied keys
shh search $regex		# list all secrets containing the regex
shh edit			# edit secret using $EDITOR
shh rotate			# rotate your key
shh serve			# start server to maintain password in memory
shh login			# login to server
shh version			# version info
shh help			# usage info
```

## Example usage:

```
# Create secret file and keys.
shh init
> creating new .shh
>
> username (usually email): alice@example.com
> password:
> confirm password:
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
> password:
> confirm password:
>
> generated ~/.config/shh/config
> generated ~/.config/shh/id_rsa
> generated ~/.config/shh/id_rsa.pub
> added bob@example.com to .ssh
>
> be sure to back up ~/.config/shh/id_rsa and remember your password, or you
> may lose access to your secrets!

# Create a secret named "database_url"
shh set database_url $DATABASE_URL

# An alternative syntax to set a secret from a file
shh set very_secret "$(< secret.txt)"

# You can also namespace the secrets like a filesystem. There's no built-in
# support for this, but it makes it easy to support different projects/repos
# within a single project.
shh set my_project/staging/database_url "127.0.0.1:3304"

# Allow a user to access a secret
shh allow bob@example.com database_url

# Deny a user from accessing a secret
shh deny bob@example.com database_url

# Deny a user from accessing all secrets. The quotes are necessary
shh deny bob@example.com "*"

# Deny a user from accessing any secrets matching a glob pattern
shh deny bob@example.com staging/*

# Show your accessible keys and meta info
shh show

# Show Bob's keys and meta info
shh show user bob@example.com

# Show all user keys and meta info
shh show user "*"

# Show all secrets containing the regular expression
shh search "example.(com|net)"

# In case of stolen key, you can regenerate/rotate your key
shh rotate
> old password:
> new password:
> confirm password:
>
> generated ~/.config/shh/id_rsa
> generated ~/.config/shh/id_rsa.pub
>
> be sure to back up ~/.config/shh/id_rsa and remember your password, or you
> may lose access to your secrets!

# Stream staging secrets to server.env on deploy
shh get staging/env | ssh alice@staging "cat > server.env"
```

## Encryption details

shh uses envelope encryption to keep your project secrets secure. `gen-key`
creates 4096-bit RSA keys in your home directory, encrypting the private key
using AES-256 with a mandated 24-char minimum length password, which is long
enough to prevent re-use/memorization and forcing use of a password manager.

Each secret is encrypted with a random AES-256 key. The AES key is encrypted
using your RSA private key and stored alongside the secret.
