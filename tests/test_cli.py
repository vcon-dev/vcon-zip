"""
Unit tests for CLI module.
"""

import json
import zipfile
import pytest
from pathlib import Path
from click.testing import CliRunner
from vcon_zip.cli import main


class TestCLI:
    """Tests for CLI commands."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()
    
    @pytest.fixture
    def sample_vcon(self, tmp_path):
        """Create a sample vCon file."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "cli-test-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        vcon_file = tmp_path / "test.json"
        vcon_file.write_text(json.dumps(vcon_data))
        return vcon_file
    
    @pytest.fixture
    def sample_bundle(self, tmp_path):
        """Create a sample bundle."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "cli-bundle-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        manifest_data = {
            "format": "vcon-bundle",
            "version": "1.0"
        }
        
        bundle_path = tmp_path / "test.vconz"
        with zipfile.ZipFile(bundle_path, 'w') as zf:
            zf.writestr('manifest.json', json.dumps(manifest_data))
            zf.writestr('vcons/cli-bundle-uuid.json', json.dumps(vcon_data))
        
        return bundle_path
    
    def test_main_no_args(self, runner):
        """Test running main with no arguments."""
        result = runner.invoke(main, [])
        
        # Click groups show help and may exit with code 0 or 2 depending on version
        # The important thing is that help text is shown
        assert 'vCon Zip Bundle' in result.output or 'Usage:' in result.output
    
    def test_main_version(self, runner):
        """Test version command."""
        result = runner.invoke(main, ['--version'])
        
        assert result.exit_code == 0
        assert '1.0.0' in result.output
    
    def test_create_command(self, runner, sample_vcon, tmp_path):
        """Test create command."""
        output = tmp_path / "output.vconz"
        
        result = runner.invoke(main, [
            'create',
            str(sample_vcon),
            '-o', str(output)
        ])
        
        assert result.exit_code == 0
        assert output.exists()
        assert 'Bundle created successfully' in result.output
    
    def test_create_command_missing_output(self, runner, sample_vcon):
        """Test create command without output fails."""
        result = runner.invoke(main, [
            'create',
            str(sample_vcon)
        ])
        
        assert result.exit_code != 0
    
    def test_extract_command(self, runner, sample_bundle, tmp_path):
        """Test extract command."""
        output_dir = tmp_path / "extracted"
        
        result = runner.invoke(main, [
            'extract',
            str(sample_bundle),
            '-d', str(output_dir)
        ])
        
        assert result.exit_code == 0
        assert output_dir.exists()
        assert 'Extracted successfully' in result.output
    
    def test_validate_command_valid_bundle(self, runner, sample_bundle):
        """Test validate command on valid bundle."""
        result = runner.invoke(main, [
            'validate',
            str(sample_bundle)
        ])
        
        assert result.exit_code == 0
        assert 'valid' in result.output.lower()
    
    def test_validate_command_verbose(self, runner, sample_bundle):
        """Test validate command with verbose flag."""
        result = runner.invoke(main, [
            'validate',
            str(sample_bundle),
            '--verbose'
        ])
        
        assert result.exit_code == 0
    
    def test_list_command(self, runner, sample_bundle):
        """Test list command."""
        result = runner.invoke(main, [
            'list',
            str(sample_bundle)
        ])
        
        assert result.exit_code == 0
        assert 'vCons' in result.output
        assert 'cli-bundle-uuid' in result.output
    
    def test_list_command_with_relationships(self, runner, sample_bundle):
        """Test list command with relationships flag."""
        result = runner.invoke(main, [
            'list',
            str(sample_bundle),
            '--show-relationships'
        ])
        
        assert result.exit_code == 0
        assert 'Relationships' in result.output
    
    def test_info_command(self, runner, sample_bundle):
        """Test info command."""
        result = runner.invoke(main, [
            'info',
            str(sample_bundle)
        ])
        
        assert result.exit_code == 0
        assert 'Format:' in result.output
        assert 'vcon-bundle' in result.output
    
    def test_analyze_command(self, runner, sample_bundle):
        """Test analyze command."""
        result = runner.invoke(main, [
            'analyze',
            str(sample_bundle)
        ])
        
        assert result.exit_code == 0
        assert 'Bundle Analysis' in result.output

