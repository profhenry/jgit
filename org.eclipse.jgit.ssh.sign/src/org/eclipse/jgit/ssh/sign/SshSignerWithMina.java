package org.eclipse.jgit.ssh.sign;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.eclipse.jgit.api.errors.CanceledException;
import org.eclipse.jgit.api.errors.JGitInternalException;
import org.eclipse.jgit.api.errors.UnsupportedSigningFormatException;
import org.eclipse.jgit.internal.transport.sshd.agent.SshAgentClient;
import org.eclipse.jgit.lib.CommitBuilder;
import org.eclipse.jgit.lib.GpgConfig;
import org.eclipse.jgit.lib.GpgObjectSigner;
import org.eclipse.jgit.lib.GpgSignature;
import org.eclipse.jgit.lib.GpgSigner;
import org.eclipse.jgit.lib.ObjectBuilder;
import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.sshd.agent.Connector;
import org.eclipse.jgit.transport.sshd.agent.ConnectorFactory;
import org.eclipse.jgit.util.Base64;
import org.eclipse.jgit.util.FS;

import de.profhenry.sshsig.core.SshSignature;
import de.profhenry.sshsig.core.SshSignatureException;
import de.profhenry.sshsig.core.SshSignatureGenerator;
import de.profhenry.sshsig.mina.ApacheMinaSshAgentEngine;

/**
 * @author profhenry
 */
public class SshSignerWithMina extends GpgSigner implements GpgObjectSigner {

	private static PublicKey readPublicKey(String aPublicKeyPath) throws Exception {

		String[] tParsedPublicKey = new String(Files.readAllBytes(Path.of(aPublicKeyPath))).split(" ");

		String tKeyType = tParsedPublicKey[0];
		byte[] tEncodedKeyData = Base64.decode(tParsedPublicKey[1]);

		PublicKeyEntryDecoder<?, ?> tPublicKeyDecoder = KeyUtils.getPublicKeyEntryDecoder(tKeyType);

		return tPublicKeyDecoder.decodePublicKey(null, tKeyType, tEncodedKeyData, null);
	}

	@Override
	public void signObject(ObjectBuilder anObject, String aGpgSigningKey, PersonIdent aCommitter,
			CredentialsProvider aCredentialsProvider, GpgConfig aConfig)
			throws CanceledException, UnsupportedSigningFormatException {

		String tKeyFile;
		// tKeyFile = "/home/jwiesner/Development/rp/git/sshsig/testkeys/test_dsa.pub";
		// tKeyFile = "/home/jwiesner/Development/rp/git/sshsig/testkeys/test_rsa.pub";
		// tKeyFile = "/home/jwiesner/Development/rp/git/sshsig/testkeys/test_ed25519.pub";
		// tKeyFile = "/home/jwiesner/.ssh/id_rsa.pub";
		tKeyFile = aGpgSigningKey;

		System.out.println("Singing object with SSH...");

		PublicKey tPublicKey;
		try {
			tPublicKey = readPublicKey(tKeyFile);
		} catch (Exception exc) {
			exc.printStackTrace();
			throw new JGitInternalException("Could not read public key!", exc);
		}

		try {
			ConnectorFactory tConnectorFactory = ConnectorFactory.getDefault();
			Connector tConnector = tConnectorFactory.create(null, FS.DETECTED.userHome());

			SshAgent tExternalSshAgent = new SshAgentClient(tConnector);

			SshSignatureGenerator<PublicKey> tSshSignatureGenerator =
					SshSignatureGenerator.create().withSigningBackend(new ApacheMinaSshAgentEngine(tExternalSshAgent));

			SshSignature tSshSignature = tSshSignatureGenerator.generateSignature(tPublicKey, "git", anObject.build());

			anObject.setGpgSignature(new GpgSignature(tSshSignature.toPem().getBytes()));
		} catch (SshSignatureException | IOException e) {
			e.printStackTrace();
			throw new JGitInternalException(e.getMessage(), e);
		}
	}

	@Override
	public boolean canLocateSigningKey(String aGpgSigningKey, PersonIdent aCommitter,
			CredentialsProvider aCredentialsProvider, GpgConfig aConfig)
			throws CanceledException, UnsupportedSigningFormatException {
		return false;
	}

	@Override
	public void sign(CommitBuilder aCommit, String aGpgSigningKey, PersonIdent aCommitter,
			CredentialsProvider aCredentialsProvider) throws CanceledException {
		throw new UnsupportedOperationException("Mööp");
	}

	@Override
	public boolean canLocateSigningKey(String aGpgSigningKey, PersonIdent aCommitter,
			CredentialsProvider aCredentialsProvider) throws CanceledException {
		throw new UnsupportedOperationException("Mööp");
	}
}
