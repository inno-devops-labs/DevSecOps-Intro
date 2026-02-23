


#### Why signing commits?
1. Signed commits authenticate the author, preventing identity spoofing, and ensure **code integrity**. Any post-signature changes invalidate it
2. Only owner of a private key can produce a valid signature that ensures **authenticity**
3. They provide **non-repudiation**, so authors can't deny contributions

Without signing, anyone can spoof user.name and user.email

#### Evidence of signed commit
![alt text](./lab3/screenshots/ssh-create.png)

Then I executed:
```bash
git config --global user.signingkey ~/.ssh/special
git config --global commit.gpgSign true
git config --global gpg.format ssh
```

And now my commits are signed:

#### 